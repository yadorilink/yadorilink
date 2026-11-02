//! `DirtyPathRepository` owns the `local_dirty_paths` table -- the local
//! journal of detected-but-not-yet-processed local edits, surviving watcher
//! misses, disk faults, and restarts.

use std::sync::Arc;
use yadorilink_sqlite_runtime::CachedStatements as _;

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::session_state::DirtyPath;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Current wall-clock time in nanoseconds since the Unix epoch, clamped to
/// `0` if the clock reads before the epoch. Same reasoning as
/// `materialization_job_repository`'s own identical duplication.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// A current, materialized file row strictly below `?2` (`?3` < path < `?4`, the bounds of the
/// names under it). The bounds are parameters so the planner uses the primary key's range.
const PRESENT_BELOW_SQL: &str =
    "SELECT 1 FROM files WHERE group_id = ?1 AND state = 'current' AND deleted = 0 \
                   AND record_kind = 'file' AND materialization_state = 'present' \
                   AND path > ?3 AND path < ?4 LIMIT 1";

/// A current, materialized file row at `?2`.
const PRESENT_AT_SQL: &str =
    "SELECT 1 FROM files WHERE group_id = ?1 AND state = 'current' AND deleted = 0 \
                   AND record_kind = 'file' AND materialization_state = 'present' \
                   AND path = ?2 LIMIT 1";

/// The most index probes the availability lookup makes per call (see
/// [`DirtyPathRepository::has_dirty_path_with_materialized_row`]).
const DIRTY_LOOKUP_PROBE_BUDGET: usize = 2_000;

pub struct DirtyPathRepository {
    database: Arc<SyncDatabase>,
}

impl DirtyPathRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Records `path` as a detected-but-not-yet-processed local edit for
    /// `group_id`, *before* the read/blockify/put/index+delta step runs. Keeps
    /// the earliest `first_seen_unix_nanos` across repeated events for the same
    /// path (so `INSERT ... ON CONFLICT` updates only the kind/observation
    /// time), and resets `attempts`/`last_error` since a fresh event is a fresh
    /// detection, not a continued failure. The row survives until
    /// [`Self::clear_dirty_path`] runs after the step commits, so a crash or a
    /// multi-second block-store fault mid-processing cannot drop the edit — the
    /// daemon re-drives it on startup and on retry.
    pub fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let now = now_unix_nanos();
        // This row is the only durable record of the edit until the real
        // index+delta write commits (see this fn's own doc comment) -- a
        // transient `SQLITE_LOCKED`/`SQLITE_BUSY` here, previously
        // unretried, meant the journal itself could silently never be
        // written for an edit that also then failed its real write for the
        // same reason, leaving no record anywhere to re-drive later.
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            conn.execute_cached(
                "INSERT INTO local_dirty_paths \
                 (group_id, path, change_kind, first_seen_unix_nanos, observed_at_unix_nanos, \
                  attempts, last_error) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL) \
                 ON CONFLICT(group_id, path) DO UPDATE SET \
                  change_kind = excluded.change_kind, \
                  observed_at_unix_nanos = excluded.observed_at_unix_nanos, \
                  attempts = 0, last_error = NULL",
                rusqlite::params![group_id, path, change_kind, now, observed_at_unix_nanos],
            )?;
            Ok(())
        })
    }

    /// Journals every `(path, change_kind, observed_at_unix_nanos)` in
    /// `entries` in one durable transaction -- the whole known batch is safe
    /// on disk before the first path's block-store/index work begins,
    /// instead of one `write()` (one `writer_gate` acquisition, one fsync)
    /// per path. Per-row semantics are identical to [`Self::record_dirty_path`]
    /// (same `ON CONFLICT` upsert, same reset of `attempts`/`last_error`);
    /// `first_seen_unix_nanos` is captured once for the whole batch rather
    /// than once per row, which only affects `list_dirty_paths`' oldest-first
    /// ordering among paths detected in the same flush and is not otherwise
    /// observable. A no-op if `entries` is empty.
    pub fn record_dirty_paths_batch(
        &self,
        group_id: &str,
        entries: &[(String, String, i64)],
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        if entries.is_empty() {
            return Ok(());
        }
        let now = now_unix_nanos();
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            permit.verify()?;
            for (path, change_kind, observed_at_unix_nanos) in entries {
                tx.execute_cached(
                    "INSERT INTO local_dirty_paths \
                     (group_id, path, change_kind, first_seen_unix_nanos, \
                      observed_at_unix_nanos, attempts, last_error) \
                     VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL) \
                     ON CONFLICT(group_id, path) DO UPDATE SET \
                      change_kind = excluded.change_kind, \
                      observed_at_unix_nanos = excluded.observed_at_unix_nanos, \
                      attempts = 0, last_error = NULL",
                    rusqlite::params![group_id, path, change_kind, now, observed_at_unix_nanos],
                )?;
            }
            Ok(())
        })
    }

    /// Records that a processing attempt for `path` failed: increments
    /// `attempts` and stores `last_error`, leaving the dirty row in place so it
    /// is retried. A no-op (updates zero rows) if the path is no longer
    /// journaled — a concurrent success may have already cleared it.
    pub fn mark_dirty_path_attempt(
        &self,
        group_id: &str,
        path: &str,
        last_error: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        permit.verify()?;
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute_cached(
                "UPDATE local_dirty_paths SET attempts = attempts + 1, last_error = ?3 \
                 WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path, last_error],
            )?;
            Ok(())
        })
    }

    /// Clears every `(path, observed_at_unix_nanos)` in `entries` from the
    /// dirty journal in one durable transaction, but only the exact
    /// observation each entry names -- conditioned on `observed_at_unix_nanos`
    /// still matching the row. A newer event for the same path (a fresh
    /// `record_dirty_path`/`record_dirty_paths_batch` call, racing in from a
    /// later flush while this batch's processing was still in flight) bumps
    /// that row's `observed_at_unix_nanos`, so this conditional delete leaves
    /// it untouched instead of erasing a not-yet-processed edit -- unlike
    /// [`Self::clear_dirty_path`], which is unconditional and must only be
    /// used when the caller holds the sole path lock for the whole window
    /// between reading and clearing. A no-op if `entries` is empty.
    pub fn clear_dirty_paths_conditional_batch(
        &self,
        group_id: &str,
        entries: &[(String, i64)],
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        if entries.is_empty() {
            return Ok(());
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            permit.verify()?;
            for (path, observed_at_unix_nanos) in entries {
                tx.execute_cached(
                    "DELETE FROM local_dirty_paths \
                     WHERE group_id = ?1 AND path = ?2 AND observed_at_unix_nanos = ?3",
                    rusqlite::params![group_id, path, observed_at_unix_nanos],
                )?;
            }
            Ok(())
        })
    }

    /// The `observed_at_unix_nanos` of `path`'s journal row, or `None` when it has none. A writer
    /// that wants to know whether the row is still the one it wrote (capture rewrites the row with
    /// its own observation when it starts on a path, and deletes it only up to that value) reads
    /// this.
    pub fn dirty_path_observed_at(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<i64>, SyncSqliteError> {
        use rusqlite::OptionalExtension as _;
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row_cached(
                    "SELECT observed_at_unix_nanos FROM local_dirty_paths \
                     WHERE group_id = ?1 AND path = ?2",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?)
        })
    }

    /// Whether `path` currently has a pending local edit journaled for
    /// `group_id`. The materialization-repair / reconcile write paths consult
    /// this before overwriting an on-disk file from the (older) index, so a
    /// newer local edit the watcher hasn't yet indexed is quarantined rather
    /// than destroyed.
    pub fn is_path_dirty(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        let count: i64 = self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row_cached(
                "SELECT COUNT(*) FROM local_dirty_paths WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )?)
        })?;
        Ok(count > 0)
    }

    /// Whether some journaled dirty path of `group_id` still has a current, materialized
    /// file row. Such a row says the bytes are here, but a pending edit or delete (of the file, or of a directory above it) may already
    /// have changed or removed them, and a copy that lives only in the folder has no other
    /// source until capture updates the row. A path with no such row (a new file) claims
    /// nothing and does not count.
    pub fn has_dirty_path_with_materialized_row(
        &self,
        group_id: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            // A dirty path stands for the file itself, the files below it (a directory
            // removed or renamed) and the files above it (a file replaced by a directory
            // whose child is journaled first). Index lookups, never a join, within a fixed probe budget.
            let mut dirty = conn.prepare_cached(
                "SELECT path FROM local_dirty_paths WHERE group_id = ?1 LIMIT ?2",
            )?;
            // A journal as long as the budget cannot be looked up within it.
            let paths: Vec<String> = dirty
                .query_map(rusqlite::params![group_id, DIRTY_LOOKUP_PROBE_BUDGET as i64], |r| {
                    r.get(0)
                })?
                .collect::<Result<_, _>>()?;
            if paths.len() >= DIRTY_LOOKUP_PROBE_BUDGET {
                return Ok(true);
            }
            let mut present = conn.prepare_cached(PRESENT_BELOW_SQL)?;
            let mut exact = conn.prepare_cached(PRESENT_AT_SQL)?;
            // Ancestors are probed once however many dirty paths share them, and a journal
            // needing more probes than the budget is a capture in full swing: the claim is
            // withdrawn rather than the status read made to wait for it.
            let mut ancestors_probed = std::collections::HashSet::new();
            let mut probes = 0usize;
            for path in &paths {
                probes += 2;
                if probes > DIRTY_LOOKUP_PROBE_BUDGET {
                    return Ok(true);
                }
                // The bounds are bound as parameters, not built in SQL, so the planner uses the
                // primary key's range.
                let (low, high) = (format!("{path}/"), format!("{path}0"));
                if exact.exists(rusqlite::params![group_id, path])?
                    || present.exists(rusqlite::params![group_id, path, low, high])?
                {
                    return Ok(true);
                }
                for (at, _) in path.match_indices('/') {
                    let ancestor = &path[..at];
                    if !ancestors_probed.insert(ancestor) {
                        continue;
                    }
                    probes += 1;
                    if probes > DIRTY_LOOKUP_PROBE_BUDGET {
                        return Ok(true);
                    }
                    if exact.exists(rusqlite::params![group_id, ancestor])? {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })
    }

    /// Every currently journaled dirty path for `group_id`, oldest-first — the
    /// daemon's startup rescan worklist. Ordered by `first_seen_unix_nanos` so
    /// the longest-outstanding edits are re-driven first.
    pub fn list_dirty_paths(&self, group_id: &str) -> Result<Vec<DirtyPath>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path, change_kind, observed_at_unix_nanos, attempts \
                 FROM local_dirty_paths WHERE group_id = ?1 \
                 ORDER BY first_seen_unix_nanos, path",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok(DirtyPath {
                    path: r.get(0)?,
                    change_kind: r.get(1)?,
                    observed_at_unix_nanos: r.get(2)?,
                    attempts: r.get::<_, i64>(3)? as u32,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }
}

#[cfg(test)]
mod tests;
