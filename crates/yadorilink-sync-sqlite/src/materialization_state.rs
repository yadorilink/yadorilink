//! `MaterializationStateRepository` owns the on-demand-sync placeholder-
//! lifecycle subset of the `files` table: `materialization_state` itself,
//! held state, and the block-liveness/eviction-candidate queries that key
//! off it. Shares the same `files` table (and the same `Arc<SyncDatabase>`
//! shape) as the sibling [`crate::file_index::FileIndexRepository`], which
//! owns plain file-record CRUD instead -- a responsibility split, not a
//! storage boundary: both share the same database and transaction model.

use std::collections::HashSet;
use std::sync::Arc;

use rusqlite::OptionalExtension;

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::file::{BlockInfo, RecordKind};
use yadorilink_replica_domain::session_state::{HeldState, MaterializationState};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Content-addressed block hash, hex-encoded.
pub type ContentHash = String;

/// Counts of non-deleted files in a group by materialization state --
/// `yadorilink status`'s per-folder summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaterializationCounts {
    pub hydrated: u64,
    pub placeholder: u64,
    /// Files being fetched (not evicted).
    pub hydrating: u64,
    /// Files being evicted: not a request for content.
    pub evicting: u64,
}

#[cfg(any(test, feature = "test-support"))]
static FAIL_STATE_READS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Test seam: while `path` is set, [`MaterializationStateRepository::get_materialization_state`]
/// fails for that path as a database read error would. Keyed by path so tests
/// running in parallel do not disturb each other.
#[cfg(any(test, feature = "test-support"))]
pub fn fail_state_reads_for_path(path: &str, fail: bool) {
    let mut paths = FAIL_STATE_READS.lock().unwrap_or_else(|p| p.into_inner());
    paths.retain(|p| p != path);
    if fail {
        paths.push(path.to_string());
    }
}

#[cfg(any(test, feature = "test-support"))]
static FAIL_PLACEHOLDER_READS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Test seam: like [`fail_state_reads_for_path`], for
/// [`MaterializationStateRepository::get_placeholder_generation`].
#[cfg(any(test, feature = "test-support"))]
pub fn fail_placeholder_reads_for_path(path: &str, fail: bool) {
    let mut paths = FAIL_PLACEHOLDER_READS.lock().unwrap_or_else(|p| p.into_inner());
    paths.retain(|p| p != path);
    if fail {
        paths.push(path.to_string());
    }
}

pub struct MaterializationStateRepository {
    database: Arc<SyncDatabase>,
}

impl MaterializationStateRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    pub fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, SyncSqliteError> {
        #[cfg(any(test, feature = "test-support"))]
        if FAIL_STATE_READS.lock().unwrap_or_else(|p| p.into_inner()).iter().any(|p| p == path) {
            return Err(SyncSqliteError::CorruptState(
                "injected materialization state read failure".into(),
            ));
        }
        self.database.read::<_, SyncSqliteError>(|conn| {
            let state: Option<String> = conn
                .query_row(
                    "SELECT materialization_state FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(state.as_deref().map(MaterializationState::from_db_str))
        })
    }

    /// The materialization state of a directory at `prefix` (`""` is the
    /// link root), read from the live files below it: hydrating while any
    /// is, then evicting, then placeholder while any file's bytes are not
    /// here, hydrated otherwise -- an empty directory included, since there
    /// is nothing of it to fetch.
    pub fn directory_materialization_state(
        &self,
        group_id: &str,
        prefix: &str,
    ) -> Result<MaterializationState, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT materialization_state FROM files WHERE group_id = ?1 AND \
                 state = 'current' AND deleted = 0 AND record_kind = 'file' AND \
                 (?2 = '' OR substr(path, 1, length(?2) + 1) = ?2 || '/')",
            )?;
            let states = stmt
                .query_map(rusqlite::params![group_id, prefix], |r| r.get::<_, String>(0))?
                .map(|state| state.map(|state| MaterializationState::from_db_str(&state)))
                .collect::<Result<Vec<_>, _>>()?;
            Ok([
                MaterializationState::Hydrating,
                MaterializationState::Evicting,
                MaterializationState::Remote,
            ]
            .into_iter()
            .find(|state| states.contains(state))
            .unwrap_or(MaterializationState::Present))
        })
    }

    pub fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            Ok(conn.execute(
                "UPDATE files SET materialization_state = ?1 \
                 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![state.as_db_str(), group_id, path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// `_in_tx` counterpart of [`Self::set_materialization_state`], for a
    /// caller that already holds an open transaction spanning more writes
    /// than just this one (bounded batching of receiver-side
    /// materialization commits): the row such a caller just upserted no longer
    /// gets `Present` from the schema's own column default (v25 changed
    /// that default to `Remote` -- see `SCHEMA_VERSION`'s doc comment),
    /// so a caller that deliberately wants `Present`-with-an-open-intent
    /// (the established crash-recoverable shape for a batched candidate
    /// whose disk publish has not landed yet) must say so explicitly now,
    /// same as every other caller of this pattern. Does not error on zero
    /// rows affected the way the non-`_in_tx` version above does -- the
    /// row was just upserted by this same transaction, so a miss here would
    /// indicate a logic error in the caller, not a legitimate "not found."
    pub fn set_materialization_state_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        path: &str,
        state: MaterializationState,
    ) -> Result<(), SyncSqliteError> {
        tx.prepare_cached(
            "UPDATE files SET materialization_state = ?1 \
             WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
        )?
        .execute(rusqlite::params![state.as_db_str(), group_id, path])?;
        Ok(())
    }

    /// Atomically changes a current file's materialization state only when
    /// it still matches `expected`. Cleanup guards use this to avoid rolling
    /// back a newer transition performed by another operation.
    pub fn transition_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        next: MaterializationState,
        permit: &RootCommitPermit,
    ) -> Result<bool, SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            Ok(conn.execute(
                "UPDATE files SET materialization_state = ?1 \
                 WHERE group_id = ?2 AND path = ?3 AND state = 'current' \
                   AND materialization_state = ?4",
                rusqlite::params![next.as_db_str(), group_id, path, expected.as_db_str()],
            )?)
        })?;
        Ok(affected == 1)
    }

    /// Like `transition_materialization_state`, but, when the caller supplies
    /// one, also requires the version the row derives to still be
    /// `expected_version`.
    ///
    /// A plain state-only CAS cannot tell "this row is still the same
    /// version this caller started working on, just still `Hydrating`"
    /// apart from "a NEWER version of this path became `current` and
    /// happened to also land in `Hydrating` before this caller's cleanup
    /// ran". A guard bounding an attempt that was about ONE version has to
    /// say so.
    ///
    /// `expected_version` is checked against
    /// [`crate::read_canonical_current_row`] inside this same
    /// transaction, because a version is not a stored column — reading it
    /// first and then updating would be two statements with nothing
    /// holding the row between them, which is the defect this parameter
    /// exists to close.
    pub fn transition_materialization_state_if_same_version(
        &self,
        group_id: &str,
        path: &str,
        expected: Option<MaterializationState>,
        expected_version: Option<&yadorilink_replica_domain::ids::VersionHash>,
        next: MaterializationState,
    ) -> Result<bool, SyncSqliteError> {
        // `expected` is exact in both directions: `None` requires the
        // column to still be NULL rather than matching anything.
        let expected_state_sql = match expected {
            Some(_) => "materialization_state = ?4",
            None => "materialization_state IS NULL AND ?4 IS NULL",
        };
        let expected_state_param: Option<&'static str> = expected.map(|s| s.as_db_str());
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            if let Some(expected_version) = expected_version {
                let live = crate::read_canonical_current_row(conn, group_id, path)?;
                if live.as_ref().is_none_or(|row| row.version_hash() != *expected_version) {
                    return Ok(0);
                }
            }
            Ok(conn.execute(
                &format!(
                    "UPDATE files SET materialization_state = ?1 \
                     WHERE group_id = ?2 AND path = ?3 AND state = 'current' \
                       AND {expected_state_sql}"
                ),
                rusqlite::params![next.as_db_str(), group_id, path, expected_state_param],
            )?)
        })?;
        Ok(affected == 1)
    }

    /// `Hydrating` is set right before a block fetch begins
    /// (`peer_session.rs`/`hydration.rs`) and only ever reset back on that
    /// same call's own failure paths — if the process is killed in
    /// between (crash, force-quit, power loss), the row stays
    /// `Hydrating` forever. A stuck `Hydrating` file is excluded from
    /// eviction *and* `build_record_for_created_or_modified` refuses to
    /// chunk it, so a real local edit to that path is silently ignored
    /// until something happens to re-hydrate it — which nothing will,
    /// since nothing believes it's still a placeholder. Called once at
    /// daemon startup (never mid-run, since a live daemon's own
    /// `Hydrating` rows are legitimately in progress) to move every
    /// stale `Hydrating` row, across every group, out of that state. The
    /// name says `Remote`, the default resolution -- safe because
    /// `Remote` just means "not fetched yet," and a startup is
    /// definitionally after any hydration that was running crashed with
    /// it -- but it is not the only one: a row over a standing proof goes
    /// back to `Present` (below), and a row repair will take keeps
    /// `Hydrating` (next paragraph).
    ///
    /// Except for a row that startup repair will take instead. A
    /// `Hydrating` row holding an open materialization intent is not an
    /// abandoned fetch: it is a write whose bytes were assembled and whose
    /// index row was committed, with a durable journal entry saying so --
    /// the shape the projected-upserts batch leaves behind between its two
    /// transactions. Repair can finish or redo those from blocks that are
    /// already local. Demoting them here first would hand them to the
    /// ordinary startup scan instead, which sees a `Remote` over
    /// bytes that do not match the row, has no way to tell a half-finished
    /// materialization from an edit made while the daemon was down, and
    /// republishes the stale bytes as a new local version.
    ///
    /// The carve-out is therefore exactly as wide as what repair will
    /// actually pick up, and no wider -- a row it declines still has to be
    /// freed here, or nothing frees it at all. Repair walks non-deleted
    /// symlink and directory rows, and non-deleted file rows with at least
    /// one block; it skips a tombstone and an empty file outright. An
    /// empty file is the reachable one: the eager batch happily carries a
    /// zero-byte version, and preserving its transient row for a pass that
    /// will never look at it leaves it wedged in that state for good,
    /// rather than merely until the next restart.
    ///
    /// And except for a row the attempt found `Present`. Access
    /// hydration and convergence rehydration both enter from `Present`
    /// (a proof about a version the row has moved off), CAS the row to
    /// `Hydrating` with no intent, and bump the mutation fence only right
    /// before they touch disk. A crash before that bump leaves `Hydrating`
    /// over a present-file proof that still stands against the path's
    /// fence -- and a standing proof means no physical write has happened
    /// since it was published, so disk holds what it vouches for or an
    /// edit nobody has journalled yet. `Remote` is the one claim
    /// access hydration reconstructs over without asking, so demoting
    /// such a row hands a user's offline edit to the next fetch or pin to
    /// overwrite. It goes back to `Present` instead: what the attempt's
    /// own guard reverts to on failure, the state under which hydrate
    /// refuses to overwrite bytes the proof does not describe, and a
    /// repair candidate that startup repair re-proves or quarantines
    /// before anything else can touch the path. A fence moved past the
    /// proof (an eviction, or an attempt that crashed after its own bump)
    /// proves nothing about disk and still resets to `Remote`. That
    /// includes an attempt that crashed after its own bump and before its
    /// write landed: a moved fence cannot be told from an evicted row's.
    /// A row with an intent stays with the carve-out above.
    /// The row does not record its entry state, so a `Remote` entry
    /// whose superseded proof still stands (a version admitted over a
    /// `Present` row strips the claim without moving the fence) comes
    /// back `Present` too; the same argument makes that claim true of its
    /// disk, and repair, not a blind reconstruct, is what then decides it.
    /// Both updates share one transaction; the count is every row moved
    /// out of `Hydrating`.
    fn reset_hydrating_in(tx: &rusqlite::Connection) -> Result<usize, SyncSqliteError> {
        let restored = tx.execute(
            "UPDATE files SET materialization_state = ?1 \
                 WHERE materialization_state = ?2 AND state = 'current' AND deleted = 0 \
                   AND COALESCE(record_kind, ?3) = ?3 \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM materialization_intents i \
                        WHERE i.group_id = files.group_id AND i.path = files.path \
                          AND i.kind = 'write' \
                   ) \
                   AND EXISTS ( \
                       SELECT 1 FROM path_materialized_generations g \
                         JOIN path_actual_mutation_fences f \
                           ON f.group_id = g.group_id AND f.path = g.path \
                        WHERE g.group_id = files.group_id AND g.path = files.path \
                          AND g.published_under_mutation_generation = f.mutation_generation \
                          AND g.object_kind = 'regular_file' \
                          AND g.version_hash IS NOT NULL \
                   )",
            rusqlite::params![
                MaterializationState::Present.as_db_str(),
                MaterializationState::Hydrating.as_db_str(),
                RecordKind::File.as_db_str(),
            ],
        )?;
        let demoted = tx.execute(
            "UPDATE files SET materialization_state = ?1 \
                 WHERE materialization_state = ?2 AND state = 'current' \
                   AND NOT ( \
                       EXISTS ( \
                           SELECT 1 FROM materialization_intents i \
                            WHERE i.group_id = files.group_id AND i.path = files.path \
                              AND i.kind = 'write' \
                       ) \
                       AND files.deleted = 0 \
                       AND ( \
                           files.record_kind IN (?3, ?5) \
                           OR ( \
                               COALESCE(files.record_kind, ?4) = ?4 \
                               AND COALESCE(files.blocks_json, '[]') NOT IN ('[]', '') \
                           ) \
                       ) \
                   )",
            rusqlite::params![
                MaterializationState::Remote.as_db_str(),
                MaterializationState::Hydrating.as_db_str(),
                RecordKind::Symlink.as_db_str(),
                // Repair reads a missing kind as `File`, so this
                // comparison has to as well, or a row with no recorded
                // kind would be reset here AND walked there.
                RecordKind::File.as_db_str(),
                RecordKind::Directory.as_db_str(),
            ],
        )?;
        Ok(restored + demoted)
    }

    /// `Evicting` is set right before eviction writes the placeholder and is
    /// cleared to `Remote` only once that placeholder is committed
    /// (`materialization_eviction::evict_file`). A crash in that window
    /// leaves the row `Evicting` forever: `reset_hydrating_in`
    /// above touches only `Hydrating` rows, `repair_interrupted_materializations`
    /// skips every non-`Present` row, and nothing else reconciles it — so
    /// the file is permanently wedged (status even miscounts it as
    /// hydrating). No blocks are ever lost: physical block reclamation
    /// happens only *after* the row has already transitioned to
    /// `Remote`, so an `Evicting` row is guaranteed to still have every
    /// block retained. Called once at daemon startup (never mid-run, since a
    /// live daemon's own `Evicting` rows are legitimately an eviction in
    /// progress) to reset every stale `Evicting` row back to `Remote`
    /// — the same target, and the same blanket-UPDATE discipline, as the
    /// `Hydrating` reset above, chosen because it is safe for both
    /// interrupted-eviction disk states:
    ///
    /// - If the placeholder was already written before the crash, the row is
    ///   now `Remote` over a placeholder file on disk — identical to a
    ///   normally completed eviction (blocks retained), which every other path
    ///   already handles.
    /// - If the crash landed *before* the placeholder write, the real content
    ///   is still fully on disk under a `Remote` row. This is the safe
    ///   direction of divergence: `Remote` means "re-fetch/verify before
    ///   trusting", so the content is preserved untouched on disk and the
    ///   ordinary hydrate/read path reconciles it later (peer-free, since the
    ///   blocks are retained) — no data loss and no spurious conflict copy.
    ///
    /// Resetting to `Present` instead would be unsafe: for the first sub-case,
    /// `repair_interrupted_materializations` would see a `Present` row whose
    /// on-disk bytes (the zero-filled placeholder) do not match the indexed
    /// blocks, quarantine that placeholder as a divergent "user edit", and
    /// journal it as a new local path — fabricating a zero-filled conflict copy.
    fn reset_evicting_in(conn: &rusqlite::Connection) -> Result<usize, SyncSqliteError> {
        Ok(conn.execute(
            "UPDATE files SET materialization_state = ?1 \
             WHERE materialization_state = ?2 AND state = 'current'",
            rusqlite::params![
                MaterializationState::Remote.as_db_str(),
                MaterializationState::Evicting.as_db_str()
            ],
        )?)
    }

    /// Both startup resets in ONE transaction, except for the rows in `keep`,
    /// which stay exactly as they are (a row whose quarantined object could
    /// not be confirmed recovered keeps its `Evicting` marker, and a row whose
    /// object cannot be inspected is not guessed about). Rows in `promote`
    /// (their object still stands) are `Present` afterwards instead of
    /// `Remote`. Returns the hydrating and evicting counts.
    pub fn reset_stale_transients(
        &self,
        keep: &[(String, String)],
        promote: &[(String, String)],
    ) -> Result<(usize, usize), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let mut kept_states = Vec::with_capacity(keep.len());
            for (group_id, path) in keep {
                let state: Option<String> = tx
                    .query_row(
                        "SELECT materialization_state FROM files \
                         WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                        rusqlite::params![group_id, path],
                        |r| r.get(0),
                    )
                    .optional()?;
                kept_states.push(state);
            }
            let hydrating = Self::reset_hydrating_in(tx)?;
            let evicting = Self::reset_evicting_in(tx)?;
            for ((group_id, path), state) in keep.iter().zip(kept_states) {
                if let Some(state) = state {
                    tx.execute(
                        "UPDATE files SET materialization_state = ?1 \
                         WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                        rusqlite::params![state, group_id, path],
                    )?;
                }
            }
            for (group_id, path) in promote {
                tx.execute(
                    "UPDATE files SET materialization_state = ?1 \
                     WHERE group_id = ?2 AND path = ?3 AND state = 'current' \
                       AND materialization_state = ?4",
                    rusqlite::params![
                        MaterializationState::Present.as_db_str(),
                        group_id,
                        path,
                        MaterializationState::Remote.as_db_str(),
                    ],
                )?;
            }
            Ok((hydrating, evicting))
        })
    }

    /// Every non-deleted row currently `Hydrating` or `Evicting`, as
    /// `(group_id, path)`: the rows a crash can have stranded. Read before the
    /// startup resets so that what they demote can be reconciled with disk.
    pub fn list_transient_rows(&self) -> Result<Vec<(String, String)>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT group_id, path FROM files \
                 WHERE state = 'current' AND deleted = 0 \
                   AND materialization_state IN ('hydrating', 'evicting')",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Counts of non-deleted files in `group_id` by materialization state
    /// — `yadorilink status`'s per-folder summary, avoiding
    /// dumping every individual file path for what's meant to be a
    /// glance-able overview (matching how `conflict_count` already
    /// summarizes rather than lists).
    /// Directories are not counted: they have no content to hydrate or
    /// evict. Symlinks are, since their rows carry a materialization state
    /// of their own.
    pub fn materialization_counts(
        &self,
        group_id: &str,
    ) -> Result<MaterializationCounts, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT materialization_state, COUNT(*) FROM files
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0
                   AND record_kind <> ?2
                 GROUP BY materialization_state",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![group_id, RecordKind::Directory.as_db_str()], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
                })?;
            let mut counts = MaterializationCounts::default();
            for row in rows {
                let (state, count) = row?;
                match MaterializationState::from_db_str(&state) {
                    MaterializationState::Present => counts.hydrated = count,
                    MaterializationState::Remote => counts.placeholder = count,
                    MaterializationState::Hydrating => counts.hydrating = count,
                    MaterializationState::Evicting => counts.evicting = count,
                }
            }
            Ok(counts)
        })
    }

    /// Bulk-loads every non-deleted file's materialization state for
    /// `group_id` (batch processing) — used by
    /// `LocalChangeProcessor::scan_existing_files` so deciding whether an
    /// on-disk entry is a placeholder (which must never be chunked) costs
    /// one query for the whole scan instead of one per file.
    pub fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashMap<String, MaterializationState>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, materialization_state FROM files \
                 WHERE group_id = ?1 AND deleted = 0 AND state = 'current'",
            )?;
            let rows = stmt
                .query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            let mut out = std::collections::HashMap::new();
            for row in rows {
                let (path, state) = row?;
                out.insert(path, MaterializationState::from_db_str(&state));
            }
            Ok(out)
        })
    }

    /// Block hashes referenced by any retained row (or live native head) other than the exact
    /// current row (and its own native head at `version`) being considered for cache eviction, and
    /// other than the current rows (and their heads) of `custodied_siblings`: placeholders whose
    /// own exact-version custody the caller has just confirmed, so that their cached blocks are
    /// no longer anyone's only local copy. The block store is device-global, so this scan crosses
    /// groups and includes placeholder, superseded, and trashed rows. A placeholder elsewhere
    /// whose custody is NOT confirmed (not in `custodied_siblings`) may still retain the only
    /// local copy because its own custody check failed.
    pub fn blocks_referenced_outside_current_file(
        &self,
        group_id: &str,
        path: &str,
        version: &yadorilink_replica_domain::ids::VersionHash,
        custodied_siblings: &[(String, String, yadorilink_replica_domain::ids::VersionHash)],
    ) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        self.blocks_referenced_outside_current_file_between(
            group_id,
            path,
            version,
            custodied_siblings,
            || {},
        )
    }

    /// [`blocks_referenced_outside_current_file`](Self::blocks_referenced_outside_current_file)
    /// with a hook run between its row read and its head read, so a test can change the database
    /// at exactly the point an unsnapshotted read would be exposed.
    ///
    /// All of it is read from ONE snapshot, for the reason
    /// [`live_block_hashes_including_native_heads`](Self::live_block_hashes_including_native_heads)
    /// is: a block that moves from a native head to a retained `files` row (or the reverse) while
    /// the sources are read one after another can be missed by every one of them.
    fn blocks_referenced_outside_current_file_between(
        &self,
        group_id: &str,
        path: &str,
        version: &yadorilink_replica_domain::ids::VersionHash,
        custodied_siblings: &[(String, String, yadorilink_replica_domain::ids::VersionHash)],
        between_reads: impl Fn(),
    ) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT group_id, path, state, blocks_json FROM files WHERE deleted = 0",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            let mut referenced = HashSet::new();
            for row in rows {
                let (row_group, row_path, row_state, blocks_json) = row?;
                let excluded = row_state == "current"
                    && ((row_group == group_id && row_path == path)
                        || custodied_siblings
                            .iter()
                            .any(|(g, p, _)| *g == row_group && *p == row_path));
                if excluded {
                    continue;
                }
                let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json)?;
                referenced.extend(blocks.into_iter().map(|block| hex::encode(block.hash)));
            }
            between_reads();
            // A custody lease held for another device roots its blocks too.
            referenced.extend(crate::remote_custody_lease::retained_block_hashes_all_groups(conn)?);
            // Blocks a recovery item keeps may be the only local copy of unsaved content.
            referenced
                .extend(crate::native_recovery_items::retained_block_hashes_all_groups(conn)?);
            // A committed native head roots its version's blocks before any `files` row
            // projects it, exactly as it does for the physical sweep. The heads of the very
            // versions being decided about are excluded, like their current rows: otherwise every
            // ordinary file (current row and head name the same blocks) would be unreclaimable.
            let mut except: Vec<(&str, &str, &yadorilink_replica_domain::ids::VersionHash)> =
                vec![(group_id, path, version)];
            except.extend(custodied_siblings.iter().map(|(g, p, v)| (g.as_str(), p.as_str(), v)));
            referenced
                .extend(crate::dag_store::native_head_retained_block_hashes_except(conn, &except)?);
            Ok(referenced)
        })
    }

    /// The other current, non-deleted regular-file rows that are placeholders (`Remote`) and
    /// share at least one of `blocks` with the file at `(group_id, path)`, as `(group, path)`.
    /// Their cached blocks are exactly what an eviction of that file would otherwise have to
    /// retain, until something asks whether they are safe to free too.
    pub fn remote_rows_sharing_blocks(
        &self,
        group_id: &str,
        path: &str,
        blocks: &[yadorilink_replica_domain::file::VersionBlock],
    ) -> Result<Vec<(String, String)>, SyncSqliteError> {
        let wanted: HashSet<String> = blocks.iter().map(|b| hex::encode(&b.hash.0)).collect();
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT group_id, path, blocks_json FROM files \
                 WHERE deleted = 0 AND state = 'current' AND materialization_state = ?1 \
                   AND record_kind = ?2 AND NOT (group_id = ?3 AND path = ?4)",
            )?;
            let rows = stmt.query_map(
                rusqlite::params![
                    MaterializationState::Remote.as_db_str(),
                    RecordKind::File.as_db_str(),
                    group_id,
                    path
                ],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
            )?;
            let mut out = Vec::new();
            for row in rows {
                let (g, p, json) = row?;
                let row_blocks: Vec<BlockInfo> = serde_json::from_str(&json)?;
                if row_blocks.iter().any(|b| wanted.contains(&hex::encode(&b.hash))) {
                    out.push((g, p));
                }
            }
            Ok(out)
        })
    }

    /// Every block hash the group's placeholders (current, non-deleted `Remote` rows) need, or
    /// `None` when that set cannot be vouched for: more than `max_files` placeholders, or a
    /// placeholder that is not a regular file (its content is not a block list). `Some(empty)`
    /// means the group has no placeholder. Read-only; a caller decides what holding the blocks
    /// locally proves.
    pub fn placeholder_block_hashes(
        &self,
        group_id: &str,
        max_files: usize,
    ) -> Result<Option<HashSet<Vec<u8>>>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT record_kind, blocks_json FROM files \
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0 \
                   AND materialization_state = ?2 AND record_kind <> ?3 \
                 LIMIT ?4",
            )?;
            let rows = stmt.query_map(
                rusqlite::params![
                    group_id,
                    MaterializationState::Remote.as_db_str(),
                    RecordKind::Directory.as_db_str(),
                    i64::try_from(max_files.saturating_add(1)).unwrap_or(i64::MAX),
                ],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )?;
            let mut hashes = HashSet::new();
            let mut files = 0usize;
            for row in rows {
                let (kind, json) = row?;
                files += 1;
                if files > max_files || kind != RecordKind::File.as_db_str() {
                    return Ok(None);
                }
                let blocks: Vec<BlockInfo> = serde_json::from_str(&json)?;
                hashes.extend(blocks.into_iter().map(|b| b.hash));
            }
            Ok(Some(hashes))
        })
    }

    /// Paths whose own index row already admits it has no bytes: an eager
    /// `placeholder`, or a `hydrating` row abandoned mid-fetch. An on-demand
    /// `placeholder` is Remote, its steady state, and is owed nothing.
    /// `peer_session::reconcile_local_materialization_audit` re-drives exactly
    /// these through an ordinary peer fetch.
    ///
    /// Deliberately NOT selected, and this must stay that way: a `hydrated` row
    /// whose bytes are missing from disk. That divergence is real, but it is
    /// not repairable from here, because two causes produce a byte-identical
    /// index row —
    ///
    ///   * a crash between the durable `Present` commit and the
    ///     temp-write-then-rename that was meant to follow it, which should be
    ///     reconstructed; and
    ///   * the user deleting or renaming the file away while the daemon was
    ///     stopped, which must NOT be reconstructed.
    ///
    /// The only thing separating them is the durable `materialization_intents`
    /// journal: the crash leaves an intent open, the offline delete does not
    /// (the intent seam in `peer_session`'s `materialize` carries a
    /// `debug_assert!` that no `Present` row is ever committed for a
    /// not-yet-written file without one, which is what makes the journal's
    /// absence meaningful rather than merely unproven). Joining that journal in
    /// here would not rescue the query either: every path returned is fed
    /// straight to `rematerialize_local_records`, which rewrites the file
    /// unconditionally — so widening to `hydrated` silently resurrects the
    /// user's deletion, and the narrow with-intent subset would still be
    /// repaired against the wrong evidence, since this is a query over the
    /// `files` table and "absent from disk" is not a fact it can observe.
    ///
    /// Nor may the caller supply that fact by stat'ing the paths: it holds no
    /// `yadorilink_root_authority::root_identity::VerifiedRoot`, and an
    /// unmounted volume leaves its mountpoint behind, so `metadata` succeeds
    /// and every `hydrated` file in the group looks absent at once.
    ///
    /// So `hydrated`-with-no-bytes is owned by
    /// `materialization_repair::repair_interrupted_materializations`, which
    /// holds both missing pieces — it takes a `VerifiedRoot`, and it branches
    /// on the intent journal, reconstructing the crash and classifying the
    /// offline delete as a deletion instead of healing it. The daemon runs
    /// that pass at startup and on a live periodic per-link cadence, and the
    /// startup disk-reconcile scan emits the resulting tombstone. This is a
    /// division of labor, not a gap in it: rows that know they need bytes are
    /// repaired over the network from here; rows that disagree with disk are
    /// repaired against disk there.
    pub fn list_materialization_repair_candidates(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            // `l.orphaned = 0` keeps this fail-closed at the storage layer: an
            // orphaned link's coordination-side authorization is permanently
            // gone, so none of its files are ever repair-eligible. The daemon
            // scheduler already filters orphaned links before calling this, but
            // the core query must not depend on that to stay correct.
            let mut stmt = conn.prepare(
                "SELECT f.path FROM files f \
                 JOIN links l ON l.group_id = f.group_id \
                 WHERE f.group_id = ?1 \
                   AND l.orphaned = 0 \
                   AND f.deleted = 0 \
                   AND f.state = 'current' \
                   AND ( \
                     (f.materialization_state = 'remote' AND l.materialization_policy = \
                      'eager') \
                     OR f.materialization_state = 'hydrating' \
                   ) \
                 ORDER BY f.path",
            )?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
    }

    /// Records that `peer_device_id` EXPLICITLY, definitively refused a
    /// fetch of `path` AT `version_hash` for lack of verified provenance on
    /// that exact version -- see `block_fetch_refusals`'s own schema doc
    /// comment for why this is deliberately distinct both from a transient
    /// miss and from any other rejection reason (never recorded here), and
    /// why it is bound to the exact version rather than just the path.
    /// Idempotent per `(group_id, path, version_hash, peer_device_id)`: a
    /// fresh rejection overwrites whatever was recorded before.
    pub fn record_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
        reason: &str,
        now_unix_nanos: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO block_fetch_refusals \
                     (group_id, path, version_hash, peer_device_id, reason, refused_at_unix_nanos) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(group_id, path, version_hash, peer_device_id) DO UPDATE SET \
                     reason = excluded.reason, \
                     refused_at_unix_nanos = excluded.refused_at_unix_nanos",
                rusqlite::params![
                    group_id,
                    path,
                    version_hash,
                    peer_device_id,
                    reason,
                    now_unix_nanos
                ],
            )?;
            Ok(())
        })
    }

    /// Deletes any refusal previously recorded for `peer_device_id` against
    /// `path` at `version_hash` -- called on a SUCCESSFUL fetch, so a peer
    /// that once refused a version but has since obtained it can never be
    /// read as still refusing it. Refusals for OTHER versions of the same
    /// path are untouched (they were never evidence about this version to
    /// begin with, since the table is version-scoped).
    pub fn clear_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM block_fetch_refusals \
                 WHERE group_id = ?1 AND path = ?2 AND version_hash = ?3 AND peer_device_id = ?4",
                rusqlite::params![group_id, path, version_hash, peer_device_id],
            )?;
            Ok(())
        })
    }

    /// Every peer device id that has EXPLICITLY refused `path` AT the exact
    /// `version_hash` (not merely never been asked, not a transient miss,
    /// and not a refusal recorded against some OTHER version of this path)
    /// -- the evidence `known_unobtainable_required_content` cross-
    /// references against the group's current authorized-writer set to
    /// positively confirm no currently-reachable peer can serve the CURRENT
    /// version's content, rather than inferring it from connectivity/timing
    /// alone or conflating it with a since-superseded version's refusals.
    pub fn refusing_peers_for_path(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
    ) -> Result<std::collections::HashSet<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT peer_device_id FROM block_fetch_refusals \
                 WHERE group_id = ?1 AND path = ?2 AND version_hash = ?3",
            )?;
            let rows = stmt.query_map(rusqlite::params![group_id, path, version_hash], |r| {
                r.get::<_, String>(0)
            })?;
            let mut out = std::collections::HashSet::new();
            for row in rows {
                out.insert(row?);
            }
            Ok(out)
        })
    }

    /// Bare `files`-table live set, with no native-head
    /// contribution — kept for callers (this module's own tests, an
    /// explicit per-group check) that want exactly that.
    pub fn live_block_hashes(&self) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        self.live_block_hashes_with_extra_roots(std::iter::empty())
    }

    /// The live set every physical block-store GC sweep must use (recovery-item blocks included):
    /// [`live_block_hashes`](Self::live_block_hashes) unioned with the blocks
    /// of every live native head in *any* group. `yadorilink-daemon`'s sweep
    /// (`gc::run_sweep_sync`) is the one production caller -- it deletes
    /// content-addressed block bytes daemon-wide, not per group, so it needs
    /// the union across every group in one query.
    ///
    /// Both halves are read from ONE snapshot. Read separately, a block could
    /// be referenced continuously and still be missed by both: a retained
    /// `files` row holds it while the heads are read, a head then takes it
    /// over and retention drops the row, and the rows are read after that.
    pub fn live_block_hashes_including_native_heads(
        &self,
    ) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        self.live_block_hashes_including_native_heads_between(|| {})
    }

    /// [`live_block_hashes_including_native_heads`](Self::live_block_hashes_including_native_heads)
    /// with a hook run between its two reads, so a test can change the
    /// database at exactly the point an unsnapshotted read would be exposed.
    fn live_block_hashes_including_native_heads_between(
        &self,
        between_reads: impl Fn(),
    ) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| live_set(conn, &between_reads))
    }

    /// Computes the GC live set from one SQLite snapshot and appends
    /// caller-provided roots. The extra-root hook is intentionally generic
    /// so a future version-history/trash table can contribute retained
    /// blocks without changing `live_block_hashes` again.
    ///
    /// This query is
    /// deliberately **not** filtered by `state` — every row with
    /// `deleted = 0` contributes its blocks regardless of whether it is
    /// `current`, `superseded`, or `trashed`, which is exactly the live-root
    /// contract a future block-store GC must honor (a block referenced by
    /// any retained version, not only the current one, is live). A
    /// `deleted = 1` row's own `blocks_json` is always `[]` (see
    /// `upsert_file_in_tx`/`mark_deleted`), so excluding it changes nothing
    /// — the *prior* live content a delete superseded is retained under
    /// `state = 'trashed'` with `deleted = 0`, and is therefore still
    /// scanned here. No code changes to `BlockStore` itself are required by
    /// this change (`delete` is still never called); this comment and
    /// `live_block_hashes_include_superseded_and_trashed_blocks` below are
    /// the load-bearing documentation of that contract for a future
    /// block-store GC implementation.
    pub fn live_block_hashes_with_extra_roots(
        &self,
        extra_roots: impl IntoIterator<Item = ContentHash>,
    ) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        // Read-only: nothing in this scan ever mutates `files`.
        let extra_roots: Vec<ContentHash> = extra_roots.into_iter().collect();
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            let mut live: HashSet<ContentHash> = extra_roots.iter().cloned().collect();
            live.extend(files_block_hashes(conn)?);
            Ok(live)
        })
    }

    /// A held file's reason and hold timestamp, so both
    /// survive a daemon restart. `None` if the row isn't currently held
    /// (either no row, or a row with no `held_reason` recorded) — the two
    /// columns are only ever written/cleared together (`set_held`/
    /// `clear_held`), so they can't independently be half-set.
    pub fn get_held_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<HeldState>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<(Option<String>, Option<i64>)> = conn
                .query_row(
                    "SELECT held_reason, held_since_unix_nanos FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            Ok(row.and_then(|(reason, since_unix_nanos)| match (reason, since_unix_nanos) {
                (Some(reason), Some(since_unix_nanos)) => {
                    Some(HeldState { reason, since_unix_nanos })
                }
                _ => None,
            }))
        })
    }

    /// Marks a file held with `reason` (e.g. `"case_collision"`,
    /// `"invalid_name"` — a free-form reason string, not a closed enum, so
    /// the hazard-detection logic that actually decides these reasons
    /// isn't constrained by this schema-only task) as of `since_unix_nanos`.
    /// Held state is purely local — a held file's index row keeps
    /// participating in normal index exchange with peers; this
    /// column is never sent over the wire.
    pub fn set_held(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        since_unix_nanos: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let affected = conn.execute(
                "UPDATE files SET held_reason = ?1, held_since_unix_nanos = ?2, held_key = NULL \
                 WHERE group_id = ?3 AND path = ?4 AND state = 'current'",
                rusqlite::params![reason, since_unix_nanos, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// [`Self::set_held`] for a hold that waits on the file itself rather
    /// than on its name, recording `key`: what the hold was decided
    /// against. A re-check whose own observation still produces `key` has
    /// nothing new to look at ([`Self::get_held_key`]). `None` records no
    /// key, so the next re-check looks again.
    pub fn set_held_with_key(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        since_unix_nanos: i64,
        key: Option<&str>,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let affected = conn.execute(
                "UPDATE files SET held_reason = ?1, held_since_unix_nanos = ?2, held_key = ?3 \
                 WHERE group_id = ?4 AND path = ?5 AND state = 'current'",
                rusqlite::params![reason, since_unix_nanos, key, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// The key [`Self::set_held_with_key`] recorded for a held path, or
    /// `None` when it is not held or was held without one.
    pub fn get_held_key(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT held_key FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                       AND held_reason IS NOT NULL",
                    rusqlite::params![group_id, path],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten())
        })
    }

    /// Every currently-held path in `group_id` — the candidate set for a
    /// periodic hazard re-check sweep. Nothing today re-evaluates a held
    /// path's hazard on its own once the SIBLING path that caused the
    /// collision changes (deleted, renamed, or itself re-admitted under a
    /// name that no longer collides): `clear_held` only ever runs as a side
    /// effect of a fresh incoming record for the SAME path, so a hold whose
    /// cause has already cleared can otherwise persist forever with no
    /// re-arm event. This listing exists to make that sweep possible; it is
    /// not itself the recheck.
    pub fn list_held_paths(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path FROM files \
                 WHERE group_id = ?1 AND state = 'current' AND held_reason IS NOT NULL",
            )?;
            let rows = stmt.query_map(rusqlite::params![group_id], |r| r.get::<_, String>(0))?;
            let mut paths = Vec::new();
            for row in rows {
                paths.push(row?);
            }
            Ok(paths)
        })
    }

    /// Clears a file's held state. A no-op, not an error, if the file
    /// wasn't held (or the row doesn't exist) — callers tombstoning a
    /// record don't first need to check whether it was ever held.
    pub fn clear_held(&self, group_id: &str, path: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "UPDATE files SET held_reason = NULL, held_since_unix_nanos = NULL, \
                 held_key = NULL \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
            )?;
            Ok(())
        })
    }

    /// `_in_tx` counterpart of [`Self::clear_held`], for a caller that
    /// already holds an open transaction spanning more writes than just
    /// this one (bounded batching of receiver-side materialization
    /// commits). Identical SQL/semantics.
    pub fn clear_held_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        tx.execute(
            "UPDATE files SET held_reason = NULL, held_since_unix_nanos = NULL, \
             held_key = NULL \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
            rusqlite::params![group_id, path],
        )?;
        Ok(())
    }

    /// Records the identity of the exact on-disk object a `write_placeholder`
    /// call just created for `group_id`/`path` — always paired with
    /// that same call's `Remote` state transition, never called on its
    /// own. `dev`/`ino` round-trip losslessly through SQLite's signed
    /// 64-bit `INTEGER` via a bit-pattern cast (`as i64`/`as u64`); the
    /// value is an opaque identity token, never interpreted as a signed
    /// number.
    pub fn record_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        identity: yadorilink_local_storage::PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            Ok(conn.execute(
                "UPDATE files SET placeholder_dev = ?1, placeholder_ino = ?2, \
                 placeholder_provider_kind = ?3 \
                 WHERE group_id = ?4 AND path = ?5 AND state = 'current'",
                rusqlite::params![
                    identity.dev as i64,
                    identity.ino as i64,
                    provider_kind,
                    group_id,
                    path
                ],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// Atomically "mint-or-read" a placeholder identity -- returns
    /// whatever identity `group_id`/`path` ends up recorded with, which is
    /// `candidate` if none was recorded yet for `provider_kind`, or the
    /// ALREADY-recorded one otherwise (`candidate` is then discarded,
    /// never written). Unlike calling `get_placeholder_generation` (a
    /// `database.read`, not serialized against this process's own writer
    /// lock) followed by a separate `record_placeholder_generation` call,
    /// this does the check-then-write in ONE `database.write` closure, so
    /// two callers racing to mint a generation for the same path (e.g. two
    /// concurrent `ListFolderFilesRequest` handlers) cannot both "win" --
    /// exactly the race a two-call read-then-insert pattern would have
    /// at its one call site
    /// (`LinkFlushHandle::ensure_windows_placeholder_generation`).
    ///
    /// Only compares against a currently-recorded identity whose
    /// `provider_kind` matches the one passed in -- a row already carrying
    /// a DIFFERENT provider's identity (e.g. `INTERNAL_INODE_PROVIDER_KIND`
    /// on a cross-platform-mismatched row) is treated as "nothing recorded
    /// for this provider yet" and overwritten with `candidate`, same as
    /// `record_placeholder_generation`'s own unconditional behavior always
    /// did for that case.
    pub fn record_placeholder_generation_if_absent(
        &self,
        group_id: &str,
        path: &str,
        candidate: yadorilink_local_storage::PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit,
    ) -> Result<yadorilink_local_storage::PlaceholderDiskIdentity, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            let existing: Option<(Option<i64>, Option<i64>, Option<String>)> = conn
                .query_row(
                    "SELECT placeholder_dev, placeholder_ino, placeholder_provider_kind \
                     FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            if let Some((Some(dev), Some(ino), Some(existing_kind))) = existing {
                if existing_kind == provider_kind {
                    return Ok(yadorilink_local_storage::PlaceholderDiskIdentity {
                        dev: dev as u64,
                        ino: ino as u64,
                    });
                }
            }
            let affected = conn.execute(
                "UPDATE files SET placeholder_dev = ?1, placeholder_ino = ?2, \
                 placeholder_provider_kind = ?3 \
                 WHERE group_id = ?4 AND path = ?5 AND state = 'current'",
                rusqlite::params![
                    candidate.dev as i64,
                    candidate.ino as i64,
                    provider_kind,
                    group_id,
                    path
                ],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(candidate)
        })
    }

    /// Clears any placeholder identity recorded for `group_id`/`path` — a
    /// no-op, not an error, if none was recorded (or the row doesn't
    /// exist). Callers use this whenever a path stops being a placeholder
    /// this process can vouch for: `write_placeholder` returning `None`
    /// (no identity capturable on this platform — see that function's own
    /// doc comment) must not leave a PRIOR call's identity behind to be
    /// wrongly trusted against the new placeholder's bytes, and a
    /// transition out of `Remote` (hydrate, or a confirmed local
    /// edit) leaves a stale identity with nothing left to identify.
    pub fn clear_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            conn.execute(
                "UPDATE files SET placeholder_dev = NULL, placeholder_ino = NULL, \
                 placeholder_provider_kind = NULL \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
            )?;
            Ok(())
        })
    }

    /// The placeholder identity recorded for `group_id`/`path`, if any.
    /// `None` — a row with no identity recorded, a row that isn't
    /// currently a placeholder at all, or no row — is not "unknown, treat
    /// as untouched": every caller of this method must treat it exactly
    /// like a later identity mismatch (fail closed), never like a
    /// confirmed match. See `crate::local_change`'s (yadorilink-local-capture)
    /// own dirty-detection doc comment for why.
    ///
    /// Deliberately filtered to `materialization_state = 'remote'`,
    /// not merely `placeholder_dev IS NOT NULL`: no production call site
    /// clears a row's identity on every transition OUT of `Remote`
    /// today (only `write_placeholder` returning `None` clears it, when a
    /// fresh placeholder write captured no identity). Without this filter, a file hydrated after
    /// being
    /// a placeholder would keep exposing its now-meaningless prior
    /// identity here, which a caller comparing against a freshly-observed
    /// disk object could wrongly read as "matches, still untouched" even
    /// though the row no longer describes a placeholder at all. Gating the
    /// read on the row's own current state closes this at the one seam
    /// every caller already goes through, without needing every hydrate/
    /// transition call site across the codebase to remember to also call
    /// `clear_placeholder_generation`.
    pub fn get_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordedPlaceholderGeneration>, SyncSqliteError> {
        #[cfg(any(test, feature = "test-support"))]
        if FAIL_PLACEHOLDER_READS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|p| p == path)
        {
            return Err(SyncSqliteError::CorruptState(
                "injected placeholder generation read failure".into(),
            ));
        }
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<(Option<i64>, Option<i64>, Option<String>)> = conn
                .query_row(
                    "SELECT placeholder_dev, placeholder_ino, placeholder_provider_kind \
                     FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                       AND materialization_state = 'remote'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            Ok(row.and_then(|(dev, ino, provider_kind)| match (dev, ino, provider_kind) {
                (Some(dev), Some(ino), Some(provider_kind)) => {
                    Some(RecordedPlaceholderGeneration {
                        identity: yadorilink_local_storage::PlaceholderDiskIdentity {
                            dev: dev as u64,
                            ino: ino as u64,
                        },
                        provider_kind,
                    })
                }
                _ => None,
            }))
        })
    }

    /// Unlike [`Self::get_placeholder_generation`], NOT gated on
    /// `materialization_state = 'remote'` -- returns whatever identity
    /// is currently on the row regardless of state. No production call site
    /// clears `placeholder_dev`/`placeholder_ino`/`placeholder_provider_kind`
    /// on the `Remote` -> `Present` transition (only an explicit
    /// [`Self::clear_placeholder_generation`] call does), so a `Present`
    /// row still exposes the generation its placeholder identity was minted
    /// under here. The Windows eviction path uses this -- reading a
    /// `Present` file's own still-recorded generation as the expected
    /// identity for the native dehydrate call's defense-in-depth check --
    /// which is exactly the "now-meaningless prior identity" scenario
    /// [`Self::get_placeholder_generation`]'s own doc comment warns a
    /// dirty-detection caller must not read; the two accessors exist because
    /// the two callers need opposite answers to the same query.
    pub fn get_recorded_placeholder_identity(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordedPlaceholderGeneration>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<(Option<i64>, Option<i64>, Option<String>)> = conn
                .query_row(
                    "SELECT placeholder_dev, placeholder_ino, placeholder_provider_kind \
                     FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            Ok(row.and_then(|(dev, ino, provider_kind)| match (dev, ino, provider_kind) {
                (Some(dev), Some(ino), Some(provider_kind)) => {
                    Some(RecordedPlaceholderGeneration {
                        identity: yadorilink_local_storage::PlaceholderDiskIdentity {
                            dev: dev as u64,
                            ino: ino as u64,
                        },
                        provider_kind,
                    })
                }
                _ => None,
            }))
        })
    }

    /// Bulk-loads every non-deleted, still-a-placeholder file's identity
    /// for `group_id` in one query — the same batch-processing shape as
    /// [`list_materialization_states`](Self::list_materialization_states),
    /// for the same reason: `LocalChangeProcessor::scan_existing_files`
    /// must not pay one query per file to decide whether an on-disk entry
    /// is still its own untouched placeholder. Filtered to
    /// `materialization_state = 'remote'` for the same reason as
    /// [`get_placeholder_generation`](Self::get_placeholder_generation).
    pub fn list_placeholder_generations(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashMap<String, RecordedPlaceholderGeneration>, SyncSqliteError>
    {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, placeholder_dev, placeholder_ino, placeholder_provider_kind \
                 FROM files \
                 WHERE group_id = ?1 AND deleted = 0 AND state = 'current' \
                   AND materialization_state = 'remote' \
                   AND placeholder_dev IS NOT NULL AND placeholder_ino IS NOT NULL \
                   AND placeholder_provider_kind IS NOT NULL",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            let mut out = std::collections::HashMap::new();
            for row in rows {
                let (path, dev, ino, provider_kind) = row?;
                out.insert(
                    path,
                    RecordedPlaceholderGeneration {
                        identity: yadorilink_local_storage::PlaceholderDiskIdentity {
                            dev: dev as u64,
                            ino: ino as u64,
                        },
                        provider_kind,
                    },
                );
            }
            Ok(out)
        })
    }

    /// The internal-mutator commit: publishes the actual-state generation
    /// for a write this device just performed, stamps the state that
    /// vouches for it, and clears the materialization intent -- all in one
    /// durable transaction, and only while the mutation fence is still the
    /// one this mutator bumped before its first mutating syscall.
    ///
    /// Use this whenever THIS device performed the write. The external
    /// lane -- [`crate::file_index::adopt_local_capture_actual_state`],
    /// reachable only from inside the local-capture upserts that admit the
    /// change alongside it -- is not interchangeable with it: adoption
    /// mints a fresh epoch, which is correct only for an external change
    /// this device is discovering after the fact. An internal mutator that
    /// adopts its own write mints an epoch no concurrent mutator can lose
    /// against, so a racing write silently keeps a proof for bytes that are
    /// no longer on disk.
    ///
    /// Losing -- either the fence moved or `expected_authoring` no longer
    /// holds -- writes nothing at all, including leaving the caller's
    /// materialization intent open, since that intent is the only record
    /// that a write was ever in flight.
    // Mirrors the free function's parameter list plus the root permit.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_internal_materialized_state_if_fence_current(
        &self,
        group_id: &str,
        path: &str,
        exact_state: &crate::exact_materialized_commit::ExactMaterializedState,
        expected_mutation_generation: i64,
        expected_authoring: Option<crate::exact_materialized_commit::ExpectedAuthoring<'_>>,
        permit: &RootCommitPermit,
    ) -> Result<crate::exact_materialized_commit::InternalMaterializedCommit, SyncSqliteError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let outcome =
                crate::exact_materialized_commit::commit_internal_materialized_state_if_fence_current(
                    tx,
                    group_id,
                    path,
                    exact_state,
                    expected_mutation_generation,
                    expected_authoring,
                    now,
                )?;
            permit.verify()?;
            Ok(outcome)
        })
    }
}

/// A placeholder identity read back from storage, paired with which
/// identity scheme produced it -- `provider_kind` matters once more than
/// one scheme exists (a real OS provider's token is not comparable against
/// [`INTERNAL_INODE_PROVIDER_KIND`](yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND)'s
/// `(dev, ino)` shape), so a caller must know which scheme it's holding
/// before comparing against a freshly-observed identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPlaceholderGeneration {
    pub identity: yadorilink_local_storage::PlaceholderDiskIdentity,
    pub provider_kind: String,
}

/// `block_fetch_refusals` binds refusal evidence to the exact version
/// refused, not just `(group_id, path, peer_device_id)`. Without that
/// binding, a refusal recorded against an OLDER version of a path could
/// be misread as evidence about a NEWER version that later
/// superseded it: author writes V1, a peer refuses V1 (recorded), the
/// author writes V2 (a distinct version, never refused by anyone) and then
/// leaves the group -- the OLD V1 refusal alone would flip V2 to
/// `AtRisk`, a false positive with no true evidence behind it. These tests
/// exercise the version binding directly at the repository layer (deterministic, no
/// topology/network involved) rather than only via the much heavier
/// full-daemon integration test.
/// The blocks of every `files` row with `deleted = 0` (see
/// [`MaterializationStateRepository::live_block_hashes_with_extra_roots`] for
/// why no row state is excluded).
/// The one computation of what a block-store sweep must keep: the blocks of every native head,
/// of every recovery item (held blocks, even of an item whose version is incomplete), and of every retained `files` row. `between_reads` runs between the
/// head read and the row read so a test can change the database where an unsnapshotted read
/// would be exposed.
pub(crate) fn live_set(
    conn: &rusqlite::Connection,
    between_reads: impl Fn(),
) -> Result<HashSet<ContentHash>, SyncSqliteError> {
    let mut live = crate::dag_store::native_head_retained_block_hashes_all_groups(conn)?;
    live.extend(crate::native_recovery_items::retained_block_hashes_all_groups(conn)?);
    live.extend(crate::remote_custody_lease::retained_block_hashes_all_groups(conn)?);
    between_reads();
    live.extend(files_block_hashes(conn)?);
    Ok(live)
}

fn files_block_hashes(
    conn: &rusqlite::Connection,
) -> Result<HashSet<ContentHash>, SyncSqliteError> {
    let mut live = HashSet::new();
    let mut stmt = conn.prepare("SELECT blocks_json FROM files WHERE deleted = 0")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    for row in rows {
        let blocks: Vec<BlockInfo> = serde_json::from_str(&row?)?;
        live.extend(blocks.into_iter().map(|block| hex::encode(block.hash)));
    }
    Ok(live)
}

#[cfg(test)]
mod block_fetch_refusal_tests;

/// `list_held_paths` is the candidate set a hazard re-check sweep walks --
/// nothing today re-evaluates a held path's hazard once the sibling that
/// caused it changes, so this listing is the piece that makes such a sweep
/// possible at all (see the method's own doc comment).
#[cfg(test)]
mod held_state_tests;

/// The startup `Hydrating` reset and the projected-upserts batch both use
/// that state, for different things, and only the materialization intent
/// tells them apart.
///
/// An abandoned block fetch is `Hydrating` with nothing else: the reset
/// owns it, and `Remote` is exactly right, because nothing was
/// written and the ordinary hydrate path will redo it.
///
/// A batch interrupted between its index commit and its finalizer is
/// `Hydrating` with an open intent: a row naming the new version, a
/// durable journal entry saying a write for it was in flight, and on-disk
/// bytes that may still be the old ones. Startup repair owns that, and can
/// finish or redo it from blocks that are already local. Demoting it first
/// hands it instead to the ordinary scan, which sees a `Remote` over
/// bytes that do not match the row and cannot tell a half-finished
/// materialization from an edit made while the daemon was down -- so it
/// republishes the stale bytes as a new local version.
#[cfg(test)]
mod stale_hydrating_reset_tests;

/// `materialization_counts` summarizes files, not directories.
#[cfg(test)]
mod counts_tests;

/// What the repair pass owes bytes to, per materialization policy.
#[cfg(test)]
mod repair_candidates_tests;

#[cfg(test)]
mod live_set_tests;
