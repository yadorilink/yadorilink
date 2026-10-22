//! `RoleLossOperationRepository` owns the `role_loss_operations` table
//! (the per-attempt role-loss journal) and the tightly-coupled
//! `durability_unknown_latches` table (a per-group "durability status
//! unknown until this device confirms otherwise" latch a role-loss handoff
//! can set) -- both durability-recovery journal state, kept in one
//! repository.

use std::sync::Arc;

use crate::error::SyncSqliteError;
use crate::read_inventory_operation_id;
use yadorilink_replica_domain::recovery::InventoryScanResult;
use yadorilink_replica_domain::session_state::{
    RoleLossAction, RoleLossOperation, RoleLossOperationParams, RoleLossOperationState,
};
use yadorilink_sqlite_runtime::SyncDatabase;

pub struct RoleLossOperationRepository {
    database: Arc<SyncDatabase>,
}

impl RoleLossOperationRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Opens a new role-loss-operation journal row in `Prepared` state,
    /// BEFORE the coordination service role-loss commit the caller is about
    /// to attempt — see [`RoleLossOperation`]'s doc comment. Replaces any
    /// existing row with the same `operation_id` (callers here always
    /// generate a fresh random id per attempt, so this is
    /// belt-and-suspenders, matching
    /// [`crate::repository::handoff_lease::HandoffLeaseRepository::record_handoff_lease`]'s
    /// own idempotent-upsert idiom).
    pub fn insert_role_loss_operation(
        &self,
        operation_id: &str,
        group_id: &str,
        op: RoleLossOperationParams<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO role_loss_operations \
                    (operation_id, group_id, source_device_id, target_device_id, lease_id, \
                     worker_membership_generation, action, state, local_path, attempts, \
                     created_at_unix, updated_at_unix) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, 'prepared', ?7, 0, ?8, ?8) \
                 ON CONFLICT(operation_id) DO UPDATE SET \
                    group_id = excluded.group_id, source_device_id = excluded.source_device_id, \
                    target_device_id = excluded.target_device_id, lease_id = excluded.lease_id, \
                    worker_membership_generation = NULL, action = excluded.action, \
                    state = 'prepared', local_path = excluded.local_path, attempts = 0, \
                    created_at_unix = excluded.created_at_unix, \
                    updated_at_unix = excluded.updated_at_unix",
                rusqlite::params![
                    operation_id,
                    group_id,
                    op.source_device_id,
                    op.target_device_id,
                    op.lease_id,
                    op.action.as_db_str(),
                    op.local_path,
                    op.now_unix,
                ],
            )?;
            Ok(())
        })
    }

    pub fn mark_role_loss_worker_committed(
        &self,
        operation_id: &str,
        membership_generation: i64,
        now_unix: i64,
    ) -> Result<bool, SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE role_loss_operations SET state = 'worker_committed', \
                 worker_membership_generation = ?1, updated_at_unix = ?2 \
                 WHERE operation_id = ?3",
                rusqlite::params![membership_generation, now_unix, operation_id],
            )?)
        })?;
        Ok(changed > 0)
    }

    pub fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO durability_unknown_latches (group_id) VALUES (?1)",
                rusqlite::params![group_id],
            )?;
            Ok(())
        })
    }

    pub fn clear_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM durability_unknown_latches WHERE group_id = ?1",
                rusqlite::params![group_id],
            )?;
            Ok(())
        })
    }

    pub fn list_durability_unknown_latches(&self) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt =
                conn.prepare("SELECT group_id FROM durability_unknown_latches ORDER BY group_id")?;
            let groups = stmt.query_map([], |row| row.get(0))?.collect::<Result<Vec<_>, _>>()?;
            Ok(groups)
        })
    }

    /// Advances a role-loss-operation journal row to `new_state`. Returns
    /// `Ok(false)` if `operation_id` no longer names a row (already deleted
    /// by a concurrent completion or by the reconciliation sweep) — every
    /// caller here treats that as a benign no-op rather than an error.
    pub fn advance_role_loss_operation(
        &self,
        operation_id: &str,
        new_state: RoleLossOperationState,
        now_unix: i64,
    ) -> Result<bool, SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE role_loss_operations SET state = ?1, updated_at_unix = ?2 \
                 WHERE operation_id = ?3",
                rusqlite::params![new_state.as_db_str(), now_unix, operation_id],
            )?)
        })?;
        Ok(changed > 0)
    }

    /// Deletes a role-loss-operation journal row — called once its outcome
    /// is fully settled: a normal success (`LocalCommitted`), or a
    /// compensation that completed (`Completed`). Idempotent: deleting an
    /// already-absent row is a no-op, matching
    /// [`yadorilink_sync_sqlite::link::LinkRepository::remove_link`]'s own
    /// idempotent delete.
    pub fn delete_role_loss_operation(&self, operation_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM role_loss_operations WHERE operation_id = ?1",
                [operation_id],
            )?;
            Ok(())
        })
    }

    /// Bumps a role-loss-operation's retry counter and returns the NEW
    /// attempt count — used by the reconciliation sweep
    /// (the daemon's `ReplicaRoleService::reconcile_role_loss`) purely to log an
    /// escalation past a bounded number of attempts. This never gates
    /// whether a retry happens: a `Compensating` row is retried
    /// indefinitely regardless of `attempts`, since giving up would leave
    /// the split state uncorrected forever (see that sweep's own doc
    /// comment).
    pub fn increment_role_loss_operation_attempts(
        &self,
        operation_id: &str,
        now_unix: i64,
    ) -> Result<i64, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "UPDATE role_loss_operations SET attempts = attempts + 1, updated_at_unix = ?1 \
                 WHERE operation_id = ?2 RETURNING attempts",
                rusqlite::params![now_unix, operation_id],
                |r| r.get(0),
            )?)
        })
    }

    /// Reads a single role-loss-operation row by id, if it still exists.
    pub fn get_role_loss_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<RoleLossOperation>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, group_id, source_device_id, target_device_id, lease_id, \
                        worker_membership_generation, action, state, local_path, attempts, \
                        created_at_unix, updated_at_unix \
                 FROM role_loss_operations WHERE operation_id = ?1",
            )?;
            let mut rows = stmt.query_map([operation_id], row_to_role_loss_operation_strict)?;
            match rows.next() {
                Some(row) => Ok(Some(row?)),
                None => Ok(None),
            }
        })
    }

    /// Every role-loss-operation row currently in one of `states` —
    /// consulted by the startup + periodic reconciliation sweep
    /// (the daemon's `ReplicaRoleService::reconcile_role_loss`), which does not
    /// filter by group id (a crash can leave a stale row behind for any
    /// group this device was ever the source of a handoff for).
    pub fn list_role_loss_operations_in_states(
        &self,
        states: &[RoleLossOperationState],
    ) -> Result<Vec<RoleLossOperation>, SyncSqliteError> {
        if states.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = states.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let sql = format!(
            "SELECT operation_id, group_id, source_device_id, target_device_id, lease_id, \
                    worker_membership_generation, action, state, local_path, attempts, \
                    created_at_unix, updated_at_unix \
             FROM role_loss_operations WHERE state IN ({placeholders}) \
             ORDER BY created_at_unix"
        );
        let state_strs: Vec<&str> = states.iter().map(|s| s.as_db_str()).collect();
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(
                rusqlite::params_from_iter(state_strs.iter()),
                row_to_role_loss_operation_strict,
            )?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Every `role_loss_operations` row, for a read-only inventory
    /// (`recovery::inventory`). Rows decode exactly as they do for the
    /// reconciliation sweep -- there is one decoder now, and it refuses an
    /// unrecognized action or state rather than coercing it to a default.
    /// What differs here is only the handling: one malformed row is
    /// isolated into `invalid` rather than aborting the whole scan,
    /// mirroring
    /// `EnrollmentRepository::scan_open_enrollment_operations`/
    /// `MembershipOperationRepository::scan_membership_operations_in_states`.
    pub fn scan_all_role_loss_operations(
        &self,
    ) -> Result<InventoryScanResult<RoleLossOperation>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, group_id, source_device_id, target_device_id, lease_id, \
                        worker_membership_generation, action, state, local_path, attempts, \
                        created_at_unix, updated_at_unix \
                 FROM role_loss_operations ORDER BY created_at_unix",
            )?;
            let mut rows = stmt.query([])?;
            let mut scan = InventoryScanResult::default();
            while let Some(row) = rows.next()? {
                let raw_state: Option<String> = row.get(7).ok();
                let Some(operation_id) = read_inventory_operation_id(row, 0)? else {
                    scan.invalid.push(
                        yadorilink_replica_domain::recovery::InvalidRecoveryOperation {
                            operation_id: None,
                            domain: yadorilink_replica_domain::recovery::RecoveryDomain::RoleLoss,
                            raw_state,
                            detail: "operation_id is not valid TEXT".to_string(),
                        },
                    );
                    continue;
                };
                match row_to_role_loss_operation_strict(row) {
                    Ok(operation) => scan.valid.push(operation),
                    Err(error) => scan.invalid.push(
                        yadorilink_replica_domain::recovery::InvalidRecoveryOperation {
                            operation_id: Some(operation_id),
                            domain: yadorilink_replica_domain::recovery::RecoveryDomain::RoleLoss,
                            raw_state,
                            detail: error.to_string(),
                        },
                    ),
                }
            }
            Ok(scan)
        })
    }

    /// Plants a role-loss-operation row with an unparseable `action` --
    /// the same kind of corruption
    /// `MembershipOperationRepository::plant_malformed_membership_operation_for_test`
    /// plants for membership, for a crate that has no access to this
    /// module's private `pool` field the way this crate's own tests do.
    ///
    /// The unparseable `action` is the whole corruption. Every other
    /// column is deliberately well-formed, `lease_id` included: it is
    /// `NOT NULL`, so a row without one is not a corrupt row this code
    /// could ever read back -- it is a row the database will not accept,
    /// and planting one tests the constraint instead of the decoder.
    #[cfg(any(test, feature = "test-support"))]
    pub fn plant_malformed_role_loss_operation_for_test(
        &self,
        operation_id: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO role_loss_operations \
                    (operation_id, group_id, source_device_id, target_device_id, lease_id, \
                     worker_membership_generation, action, state, local_path, attempts, \
                     created_at_unix, updated_at_unix) \
                 VALUES (?1, 'group-1', 'device-c', 'device-d', 'lease-1', NULL, \
                    'not-a-real-action', 'prepared', NULL, 0, 1, 1)",
                rusqlite::params![operation_id],
            )?;
            Ok(())
        })
    }
}

fn role_loss_decode_error(column_index: usize, detail: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column_index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, detail.into())),
    )
}

pub fn row_to_role_loss_operation_strict(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<RoleLossOperation> {
    let action_raw: String = r.get(6)?;
    let state_raw: String = r.get(7)?;
    let action = RoleLossAction::try_from_db_str(&action_raw)
        .map_err(|error| role_loss_decode_error(6, error))?;
    let state = RoleLossOperationState::try_from_db_str(&state_raw)
        .map_err(|error| role_loss_decode_error(7, error))?;
    let attempts: i64 = r.get(9)?;
    if attempts < 0 {
        return Err(role_loss_decode_error(9, format!("negative role-loss attempts: {attempts}")));
    }
    Ok(RoleLossOperation {
        operation_id: r.get(0)?,
        group_id: r.get(1)?,
        source_device_id: r.get(2)?,
        target_device_id: r.get(3)?,
        lease_id: r.get(4)?,
        worker_membership_generation: r.get(5)?,
        action,
        state,
        local_path: r.get(8)?,
        attempts,
        created_at_unix: r.get(10)?,
        updated_at_unix: r.get(11)?,
    })
}
