//! `MembershipOperationRepository` owns the `membership_operations` table
//! -- the per-attempt journal for a device-membership mutation
//! (revoke/replace) that may commit at the coordination worker before this
//! device's local recovery-scope bookkeeping is confirmed.
//! `recovery_local_snapshot` stays on `SyncState`, untouched: it reads a
//! SINGLE snapshot across whichever of `links`, `pending_enrollments`,
//! `enrollment_operations`, `membership_operations`,
//! `role_loss_operations`, and `durability_unknown_latches` its
//! `RecoveryDomain` needs, all inside one `Deferred` SQLite transaction --
//! genuinely cross-cluster (Enrollment/ Membership/RoleLoss/Link,
//! depending on the key's domain), not a single table this repository (or
//! any other single repository) owns. Moving it here would mean either
//! reaching into every sibling repository's own `pool()`/table internals
//! from outside, or duplicating its three domain-dispatch helpers
//! (`snapshot_enrollment_in_tx`/
//! `snapshot_membership_in_tx`/`snapshot_role_loss_in_tx`) across
//! repository boundaries -- out of scope for this commit, and a better fit
//! for a future cross-repository read/commit-store pass.

use std::sync::Arc;

use crate::error::SyncSqliteError;
use crate::read_inventory_operation_id;
use yadorilink_replica_domain::recovery::InventoryScanResult;
use yadorilink_replica_domain::session_state::{
    InvalidMembershipOperation, MembershipCommitMode, MembershipDurabilityScope,
    MembershipOperation, MembershipOperationAction, MembershipOperationScan,
    MembershipOperationState,
};
use yadorilink_sqlite_runtime::SyncDatabase;

pub struct MembershipOperationRepository {
    database: Arc<SyncDatabase>,
}

impl MembershipOperationRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Opens a new membership-operation journal row — see
    /// [`MembershipOperation`]'s doc comment. Unlike
    /// [`crate::repository::role_loss_operation::RoleLossOperationRepository::insert_role_loss_operation`]'s
    /// idempotent-upsert idiom, an existing row under the same
    /// `operation_id` is NEVER overwritten: `operation_id` is a fresh UUID
    /// minted by the caller for every new mutation, so a conflict here means
    /// either a genuine (astronomically rare) UUID collision or a bug --
    /// either way, silently clobbering whatever the existing row already
    /// recorded could destroy in-flight recovery state. Returns `Ok(false)`
    /// (not an error) on conflict, so the caller can retry under a fresh id
    /// -- see `replica_membership_service.rs`'s `open_membership_operation`.
    #[allow(clippy::too_many_arguments)]
    pub fn try_insert_membership_operation(
        &self,
        operation_id: &str,
        action: MembershipOperationAction,
        commit_mode: MembershipCommitMode,
        removed_device_id: &str,
        group_ids: &[String],
        target_device_ids: &[String],
        lease_ids: &[Option<String>],
        state: MembershipOperationState,
        durability_scope: MembershipDurabilityScope,
        latch_group_ids: &[String],
        last_error: Option<&str>,
        now_unix: i64,
    ) -> Result<bool, SyncSqliteError> {
        let group_ids_json = serde_json::to_string(group_ids)?;
        let target_device_ids_json = serde_json::to_string(target_device_ids)?;
        let lease_ids_json = serde_json::to_string(lease_ids)?;
        let latch_group_ids_json = serde_json::to_string(latch_group_ids)?;
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "INSERT INTO membership_operations \
                    (operation_id, action, commit_mode, removed_device_id, group_ids, \
                     target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                     last_error, created_at_unix, updated_at_unix) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12) \
                 ON CONFLICT(operation_id) DO NOTHING",
                rusqlite::params![
                    operation_id,
                    action.as_db_str(),
                    commit_mode.as_db_str(),
                    removed_device_id,
                    &group_ids_json,
                    &target_device_ids_json,
                    &lease_ids_json,
                    state.as_db_str(),
                    durability_scope.as_db_str(),
                    &latch_group_ids_json,
                    last_error,
                    now_unix,
                ],
            )?)
        })?;
        Ok(changed == 1)
    }

    /// Advances a membership-operation journal row to `new_state`. Returns
    /// `Ok(false)` if `operation_id` no longer names a row.
    pub fn mark_membership_operation_state(
        &self,
        operation_id: &str,
        new_state: MembershipOperationState,
        last_error: Option<&str>,
        now_unix: i64,
    ) -> Result<bool, SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE membership_operations SET state = ?1, last_error = ?2, \
                    updated_at_unix = ?3 \
                 WHERE operation_id = ?4",
                rusqlite::params![new_state.as_db_str(), last_error, now_unix, operation_id],
            )?)
        })?;
        Ok(changed > 0)
    }

    /// Deletes a membership-operation journal row — idempotent, matching
    /// [`crate::repository::role_loss_operation::RoleLossOperationRepository::delete_role_loss_operation`].
    pub fn delete_membership_operation(&self, operation_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM membership_operations WHERE operation_id = ?1",
                [operation_id],
            )?;
            Ok(())
        })
    }

    /// Reads a single membership-operation row by id, if it still exists.
    pub fn get_membership_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<MembershipOperation>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, action, commit_mode, removed_device_id, group_ids, \
                        target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                        last_error, created_at_unix, updated_at_unix \
                 FROM membership_operations WHERE operation_id = ?1",
            )?;
            let mut rows = stmt.query_map([operation_id], row_to_membership_operation)?;
            match rows.next() {
                Some(row) => Ok(Some(row?)),
                None => Ok(None),
            }
        })
    }

    /// Every `membership_operations` row, with NO state filter at all --
    /// unlike [`Self::scan_membership_operations_in_states`], whose
    /// `WHERE state IN (...)` allow-list silently excludes a row whose
    /// `state` column is some UNKNOWN string (it matches none of the bound
    /// placeholders, so it is neither `valid` nor `invalid` -- simply
    /// invisible). A read-only inventory (`recovery::inventory`) must never
    /// have that blind spot: passing it every KNOWN state still leaves
    /// exactly the malformed/forward-version rows it most needs to surface
    /// unreachable. This scan has no such gap by construction.
    pub fn scan_all_membership_operations(
        &self,
    ) -> Result<InventoryScanResult<MembershipOperation>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, action, commit_mode, removed_device_id, group_ids, \
                        target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                        last_error, created_at_unix, updated_at_unix \
                 FROM membership_operations ORDER BY created_at_unix",
            )?;
            let mut rows = stmt.query([])?;
            let mut scan = InventoryScanResult::default();
            while let Some(row) = rows.next()? {
                let raw_state: Option<String> = row.get(7).ok();
                let Some(operation_id) = read_inventory_operation_id(row, 0)? else {
                    scan.invalid.push(
                        yadorilink_replica_domain::recovery::InvalidRecoveryOperation {
                            operation_id: None,
                            domain: yadorilink_replica_domain::recovery::RecoveryDomain::Membership,
                            raw_state,
                            detail: "operation_id is not valid TEXT".to_string(),
                        },
                    );
                    continue;
                };
                match row_to_membership_operation(row) {
                    Ok(operation) => scan.valid.push(operation),
                    Err(error) => scan.invalid.push(
                        yadorilink_replica_domain::recovery::InvalidRecoveryOperation {
                            operation_id: Some(operation_id),
                            domain: yadorilink_replica_domain::recovery::RecoveryDomain::Membership,
                            raw_state,
                            detail: error.to_string(),
                        },
                    ),
                }
            }
            Ok(scan)
        })
    }

    /// Every membership-operation row NOT in a terminal or blocked state
    /// (`completed`/`definitely_rejected`/`recovery-blocked`) -- unlike
    /// [`Self::scan_membership_operations_in_states`]'s allow-list, this
    /// also catches a row whose `state` column is some UNKNOWN string (a
    /// downgrade, a bug, manual tampering): an allow-list silently excludes
    /// such a row from every sweep forever, while this deny-list still
    /// selects it, so `row_to_membership_operation`'s strict decode runs on
    /// it and reports it in `invalid` for the caller to mark
    /// `RecoveryBlocked` explicitly rather than leaving it to rot
    /// unreachable.
    pub fn scan_open_membership_operations(
        &self,
    ) -> Result<MembershipOperationScan, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, action, commit_mode, removed_device_id, group_ids, \
                        target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                        last_error, created_at_unix, updated_at_unix \
                 FROM membership_operations \
                 WHERE state NOT IN ('completed', 'definitely_rejected', 'recovery-blocked') \
                 ORDER BY created_at_unix",
            )?;
            let rows = stmt.query([])?;
            Self::collect_membership_operation_scan(rows)
        })
    }

    fn collect_membership_operation_scan(
        mut rows: rusqlite::Rows<'_>,
    ) -> Result<MembershipOperationScan, SyncSqliteError> {
        let mut scan = MembershipOperationScan::default();
        while let Some(row) = rows.next()? {
            let operation_id: String = row.get(0)?;
            let raw_state: Option<String> = row.get(7).ok();
            match row_to_membership_operation(row) {
                Ok(operation) => scan.valid.push(operation),
                Err(error) => scan.invalid.push(InvalidMembershipOperation {
                    operation_id,
                    raw_state,
                    detail: error.to_string(),
                }),
            }
        }
        Ok(scan)
    }

    /// Whether ANY membership-operation row currently has an unresolved
    /// (not `Completed`/`DefinitelyRejected`) `Unknown` durability scope --
    /// the fast account-wide check `group_durability_status` needs, without
    /// scanning and fully decoding every row (a malformed row must still
    /// force degraded status, so this counts rows rather than decoding
    /// them).
    pub fn has_open_unknown_durability_scope_operation(&self) -> Result<bool, SyncSqliteError> {
        let count: i64 = self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM membership_operations \
                 WHERE durability_scope = 'unknown' \
                   AND state NOT IN ('completed', 'definitely_rejected')",
                [],
                |r| r.get(0),
            )?)
        })?;
        Ok(count > 0)
    }

    /// Whether ANY membership-operation row is currently `RecoveryBlocked`.
    /// A row reaches this state only when automatic recovery was refused
    /// outright (an operation_id conflict, a local/remote request-identity
    /// mismatch, or a malformed journal row) -- a KNOWN-scope row that
    /// reaches it after its remote mutation already committed means this
    /// device cannot currently confirm whether its forced groups are
    /// durably latched, so the account-wide status must fail closed the
    /// same way an open `Unknown`-durability-scope row already does.
    pub fn has_recovery_blocked_membership_operation(&self) -> Result<bool, SyncSqliteError> {
        let count: i64 = self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM membership_operations WHERE state = 'recovery-blocked'",
                [],
                |r| r.get(0),
            )?)
        })?;
        Ok(count > 0)
    }

    /// Plants a `membership_operations` row with a malformed `group_ids`
    /// column (not valid JSON) under `operation_id` -- the same kind of
    /// corruption a recovery-inventory `invalid`-row test needs, but usable
    /// from a DIFFERENT crate's test build (e.g. yadorilink-daemon's), which
    /// has no access to this module's private `pool` field the way this
    /// crate's own tests do via raw `state.pool().get()...execute(...)` calls.
    #[cfg(any(test, feature = "test-support"))]
    pub fn plant_malformed_membership_operation_for_test(
        &self,
        operation_id: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO membership_operations \
                    (operation_id, action, commit_mode, removed_device_id, group_ids, \
                     target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                     last_error, created_at_unix, updated_at_unix) \
                 VALUES (?1, 'revoke', 'plain-revoke', 'device-b', 'not-a-json-array', '[]', '[]', \
                    'prepared', 'known', '[]', NULL, 1, 1)",
                rusqlite::params![operation_id],
            )?;
            Ok(())
        })
    }
}

fn membership_decode_error(column_index: usize, detail: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column_index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, detail.into())),
    )
}

/// Mode-specific shape validation for a decoded [`MembershipOperation`]'s
/// `group_ids`/`target_device_ids`/`lease_ids` -- a row whose `commit_mode`
/// doesn't match the arity its own dispatch code assumes (e.g. `PlainRevoke`
/// with zero groups, or `GuardedRevoke` with a missing lease) would index
/// out of bounds or silently misfire a remote call, so this is checked
/// before a row is ever handed to a reconciler.
fn validate_membership_operation_shape(
    mode: MembershipCommitMode,
    group_ids: &[String],
    target_device_ids: &[String],
    lease_ids: &[Option<String>],
) -> Result<(), String> {
    match mode {
        MembershipCommitMode::PlainRevoke => {
            if group_ids.len() != 1 || !target_device_ids.is_empty() || !lease_ids.is_empty() {
                return Err(
                    "plain-revoke requires exactly one group and no targets or leases".to_string()
                );
            }
        }
        MembershipCommitMode::GuardedRevoke => {
            if group_ids.len() != 1
                || target_device_ids.len() != 1
                || lease_ids.len() != 1
                || lease_ids[0].is_none()
            {
                return Err(
                    "guarded-revoke requires one group, one target, and one lease".to_string()
                );
            }
        }
        MembershipCommitMode::PlainRemoveDevice => {
            if !group_ids.is_empty() || !target_device_ids.is_empty() || !lease_ids.is_empty() {
                return Err("plain-remove-device must not contain group, target, or lease arrays"
                    .to_string());
            }
        }
        MembershipCommitMode::HandoffRemoveDevice => {
            if group_ids.is_empty()
                || group_ids.len() != target_device_ids.len()
                || group_ids.len() != lease_ids.len()
                || lease_ids.iter().any(Option::is_none)
            {
                return Err(
                    "handoff-remove-device requires equally-sized non-empty group, target, and \
                     lease arrays"
                        .to_string(),
                );
            }
        }
    }
    if group_ids.iter().any(String::is_empty) || target_device_ids.iter().any(String::is_empty) {
        return Err("membership operation contains an empty identifier".to_string());
    }
    Ok(())
}

pub fn row_to_membership_operation(r: &rusqlite::Row<'_>) -> rusqlite::Result<MembershipOperation> {
    let action_raw: String = r.get(1)?;
    let mode_raw: String = r.get(2)?;
    let group_ids_raw: String = r.get(4)?;
    let target_device_ids_raw: String = r.get(5)?;
    let lease_ids_raw: String = r.get(6)?;
    let state_raw: String = r.get(7)?;
    let durability_scope_raw: String = r.get(8)?;
    let latch_group_ids_raw: String = r.get(9)?;

    let action = MembershipOperationAction::try_from_db_str(&action_raw)
        .map_err(|error| membership_decode_error(1, error))?;
    let commit_mode = MembershipCommitMode::try_from_db_str(&mode_raw)
        .map_err(|error| membership_decode_error(2, error))?;
    let group_ids: Vec<String> = serde_json::from_str(&group_ids_raw)
        .map_err(|error| membership_decode_error(4, error.to_string()))?;
    let target_device_ids: Vec<String> = serde_json::from_str(&target_device_ids_raw)
        .map_err(|error| membership_decode_error(5, error.to_string()))?;
    let lease_ids: Vec<Option<String>> = serde_json::from_str(&lease_ids_raw)
        .map_err(|error| membership_decode_error(6, error.to_string()))?;
    let state = MembershipOperationState::try_from_db_str(&state_raw)
        .map_err(|error| membership_decode_error(7, error))?;
    let durability_scope = MembershipDurabilityScope::try_from_db_str(&durability_scope_raw)
        .map_err(|error| membership_decode_error(8, error))?;
    let latch_group_ids: Vec<String> = serde_json::from_str(&latch_group_ids_raw)
        .map_err(|error| membership_decode_error(9, error.to_string()))?;

    validate_membership_operation_shape(commit_mode, &group_ids, &target_device_ids, &lease_ids)
        .map_err(|error| membership_decode_error(2, error))?;

    Ok(MembershipOperation {
        operation_id: r.get(0)?,
        action,
        commit_mode,
        removed_device_id: r.get(3)?,
        group_ids,
        target_device_ids,
        lease_ids,
        state,
        durability_scope,
        latch_group_ids,
        last_error: r.get(10)?,
        created_at_unix: r.get(11)?,
        updated_at_unix: r.get(12)?,
    })
}
