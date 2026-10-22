//! `RewindRunRepository` owns the `rewind_runs` table: one row per
//! folder-rewind execution, recording how far it got.
//!
//! The row is progress, never the namespace's truth. What a rewind changed
//! is the ordinary signed changes it authored; nothing here is used to
//! resume a run or to infer what is on disk. That is why an interruption is
//! settled from the row alone (see [`RewindRunRepository::interrupt_run`]).

use std::sync::Arc;

use rusqlite::OptionalExtension;
use yadorilink_replica_domain::rewind::{
    RewindFailureKind, RewindPlanId, RewindRun, RewindRunState,
};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;

/// The SQL form of [`RewindRunState::is_active`].
const ACTIVE_STATES: &str = "('planned', 'prefetched', 'committing')";

/// The outcome of [`RewindRunRepository::begin_run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewindRunStart {
    /// The run was recorded as [`RewindRunState::Planned`].
    Started,
    /// The group already has an unfinished run (this one: `run_id`).
    /// Nothing was written.
    ActiveRunExists { run_id: String },
}

pub struct RewindRunRepository {
    database: Arc<SyncDatabase>,
}

impl RewindRunRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    pub(crate) fn database(&self) -> &Arc<SyncDatabase> {
        &self.database
    }

    /// Records a new run of `group_id` as [`RewindRunState::Planned`],
    /// unless the group already has an unfinished one.
    pub fn begin_run(
        &self,
        run_id: &str,
        group_id: &str,
        target_unix_nanos: i64,
        plan_id: &RewindPlanId,
        created_at_unix_nanos: i64,
    ) -> Result<RewindRunStart, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let active: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT run_id FROM rewind_runs \
                         WHERE group_id = ?1 AND state IN {ACTIVE_STATES}"
                    ),
                    [group_id],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(run_id) = active {
                return Ok(RewindRunStart::ActiveRunExists { run_id });
            }
            tx.execute(
                "INSERT INTO rewind_runs \
                    (run_id, group_id, target_unix_nanos, plan_id, state, created_at_unix_nanos) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    run_id,
                    group_id,
                    target_unix_nanos,
                    plan_id.0.as_slice(),
                    RewindRunState::Planned.as_db_str(),
                    created_at_unix_nanos,
                ],
            )?;
            Ok(RewindRunStart::Started)
        })
    }

    /// `planned` -> `prefetched`: every byte the plan needs is held locally
    /// and verified, and the run will commit `chunks_total` chunks.
    pub fn mark_prefetched(&self, run_id: &str, chunks_total: u64) -> Result<(), SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE rewind_runs SET state = 'prefetched', chunks_total = ?2 \
                 WHERE run_id = ?1 AND state = 'planned'",
                rusqlite::params![run_id, chunks_total as i64],
            )?)
        })?;
        if changed == 0 {
            return Err(SyncSqliteError::CorruptState(format!(
                "rewind run {run_id} is not planned, so it cannot become prefetched"
            )));
        }
        Ok(())
    }

    /// Ends an unfinished run that changed nothing as
    /// [`RewindRunState::Failed`] with `kind`. Refused for a run that
    /// committed a chunk: a failed run always made zero mutations, and one
    /// that made some is [`RewindRunState::NeedsReplan`] instead.
    ///
    /// `unavailable_files` is the N of [`RewindFailureKind::ContentUnavailable`]
    /// and `offline_devices` the members that were not connected for
    /// [`RewindFailureKind::Transient`]; pass zero / empty otherwise.
    pub fn mark_failed(
        &self,
        run_id: &str,
        kind: RewindFailureKind,
        unavailable_files: u64,
        offline_devices: &[String],
    ) -> Result<(), SyncSqliteError> {
        let offline = serde_json::to_string(offline_devices)?;
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                &format!(
                    "UPDATE rewind_runs \
                     SET state = 'failed', failure_kind = ?2, unavailable_files = ?3, \
                         offline_devices_json = ?4 \
                     WHERE run_id = ?1 AND state IN {ACTIVE_STATES} AND chunks_done = 0"
                ),
                rusqlite::params![run_id, kind.as_db_str(), unavailable_files as i64, offline],
            )?)
        })?;
        if changed == 0 {
            return Err(SyncSqliteError::CorruptState(format!(
                "rewind run {run_id} is not an unfinished run without committed chunks"
            )));
        }
        Ok(())
    }

    /// `prefetched` -> `done` for a run with no chunk to commit (a plan with
    /// nothing to change).
    pub fn finish_empty_run(&self, run_id: &str) -> Result<(), SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE rewind_runs SET state = 'done' \
                 WHERE run_id = ?1 AND state = 'prefetched' AND chunks_total = 0",
                [run_id],
            )?)
        })?;
        if changed == 0 {
            return Err(SyncSqliteError::CorruptState(format!(
                "rewind run {run_id} is not a prefetched run without chunks"
            )));
        }
        Ok(())
    }

    /// Ends an unfinished run whose commit phase stopped: a chunk was
    /// refused or found the folder changed, or a local failure stopped it.
    /// Decided from the row, in one transaction: a run that committed a
    /// chunk becomes [`RewindRunState::NeedsReplan`] (those changes stay as
    /// ordinary changes), one that committed none becomes
    /// [`RewindRunState::Failed`] with `kind`. Returns the state it ended in.
    pub fn stop_run(
        &self,
        run_id: &str,
        kind: RewindFailureKind,
    ) -> Result<RewindRunState, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let replan = tx.execute(
                "UPDATE rewind_runs SET state = 'needs_replan' \
                 WHERE run_id = ?1 AND state = 'committing' AND chunks_done > 0",
                [run_id],
            )?;
            if replan > 0 {
                return Ok(RewindRunState::NeedsReplan);
            }
            let failed = tx.execute(
                &format!(
                    "UPDATE rewind_runs SET state = 'failed', failure_kind = ?2 \
                     WHERE run_id = ?1 AND state IN {ACTIVE_STATES} AND chunks_done = 0"
                ),
                rusqlite::params![run_id, kind.as_db_str()],
            )?;
            if failed == 0 {
                return Err(SyncSqliteError::CorruptState(format!(
                    "rewind run {run_id} is not unfinished, so it cannot be stopped"
                )));
            }
            Ok(RewindRunState::Failed)
        })
    }

    /// Settles `run_id` after its execution stopped without ending it (the
    /// task was dropped). The same rule as
    /// [`Self::interrupt_unfinished_runs`]; no-op for a run that already
    /// ended. Returns whether the row changed.
    pub fn interrupt_run(&self, run_id: &str) -> Result<bool, SyncSqliteError> {
        Ok(self.interrupt(Some(run_id))? > 0)
    }

    /// Settles every unfinished run. Called once at daemon start, before
    /// anything can begin a new run, so every unfinished row belongs to a
    /// process that is gone. Returns how many rows changed.
    ///
    /// Decided from the row alone, never from the folder: a run that
    /// committed a chunk becomes [`RewindRunState::NeedsReplan`] (those
    /// changes stay as ordinary changes; the person previews again), and
    /// any other unfinished run -- planned, prefetched, or committing with
    /// no chunk committed, a chunk being one atomic transaction -- changed
    /// nothing and becomes [`RewindRunState::Failed`] /
    /// [`RewindFailureKind::Interrupted`]. No run is ever resumed.
    pub fn interrupt_unfinished_runs(&self) -> Result<usize, SyncSqliteError> {
        self.interrupt(None)
    }

    fn interrupt(&self, run_id: Option<&str>) -> Result<usize, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let only = if run_id.is_some() { " AND run_id = ?1" } else { "" };
            let params: Vec<&dyn rusqlite::ToSql> = match &run_id {
                Some(id) => vec![id as &dyn rusqlite::ToSql],
                None => Vec::new(),
            };
            let replan = tx.execute(
                &format!(
                    "UPDATE rewind_runs SET state = 'needs_replan' \
                     WHERE state = 'committing' AND chunks_done > 0{only}"
                ),
                params.as_slice(),
            )?;
            let failed = tx.execute(
                &format!(
                    "UPDATE rewind_runs SET state = 'failed', failure_kind = 'interrupted' \
                     WHERE state IN {ACTIVE_STATES} AND chunks_done = 0{only}"
                ),
                params.as_slice(),
            )?;
            Ok(replan + failed)
        })
    }

    pub fn get_run(&self, run_id: &str) -> Result<Option<RewindRun>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            conn.query_row(
                &format!("SELECT {COLUMNS} FROM rewind_runs WHERE run_id = ?1"),
                [run_id],
                run_from_row,
            )
            .optional()?
            .transpose()
        })
    }

    /// The group's most recently started run, if any.
    pub fn latest_run(&self, group_id: &str) -> Result<Option<RewindRun>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {COLUMNS} FROM rewind_runs WHERE group_id = ?1 \
                     ORDER BY created_at_unix_nanos DESC, run_id DESC LIMIT 1"
                ),
                [group_id],
                run_from_row,
            )
            .optional()?
            .transpose()
        })
    }
}

const COLUMNS: &str = "run_id, group_id, target_unix_nanos, plan_id, state, chunks_done, \
                       unavailable_files, failure_kind, created_at_unix_nanos, \
                       offline_devices_json, chunks_total, restored, deleted";

fn run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<RewindRun, SyncSqliteError>> {
    let run_id: String = row.get(0)?;
    let plan_id: Vec<u8> = row.get(3)?;
    let state: String = row.get(4)?;
    let failure_kind: Option<String> = row.get(7)?;
    let offline_devices: String = row.get(9)?;
    let decoded = (|| {
        let plan_id: [u8; 32] = plan_id.as_slice().try_into().map_err(|_| {
            SyncSqliteError::CorruptState(format!("rewind run {run_id}: plan id is not 32 bytes"))
        })?;
        let state = RewindRunState::from_db_str(&state).map_err(SyncSqliteError::CorruptState)?;
        let failure_kind = failure_kind
            .as_deref()
            .map(RewindFailureKind::from_db_str)
            .transpose()
            .map_err(SyncSqliteError::CorruptState)?;
        let offline_devices: Vec<String> = serde_json::from_str(&offline_devices)?;
        Ok((RewindPlanId(plan_id), state, failure_kind, offline_devices))
    })();
    let (plan_id, state, failure_kind, offline_devices) = match decoded {
        Ok(decoded) => decoded,
        Err(error) => return Ok(Err(error)),
    };
    Ok(Ok(RewindRun {
        run_id,
        group_id: row.get(1)?,
        target_unix_nanos: row.get(2)?,
        plan_id,
        state,
        chunks_done: row.get::<_, i64>(5)? as u64,
        unavailable_files: row.get::<_, i64>(6)? as u64,
        failure_kind,
        offline_devices,
        chunks_total: row.get::<_, i64>(10)? as u64,
        restored: row.get::<_, i64>(11)? as u64,
        deleted: row.get::<_, i64>(12)? as u64,
        created_at_unix_nanos: row.get(8)?,
    }))
}

#[cfg(test)]
mod tests;
