//! `RecoverySnapshotReader` answers "what local evidence exists for one
//! `(domain, operation_id)` recovery key, all read from a SINGLE
//! consistent point in time" -- genuinely cross-cluster, spanning `links`,
//! `pending_enrollments`, `enrollment_operations`,
//! `membership_operations`, `durability_unknown_latches`, and
//! `role_loss_operations` depending on the key's domain. Not a
//! single-table repository, and not an atomic WRITE transaction either
//! (this type never writes) -- it holds a plain `Arc<SyncDatabase>`, same
//! shape as every other repository, but exists purely for its own
//! consistent-read-snapshot reason: reading each table independently
//! through the owning repository (`LinkRepository:: link_gate_for_group`,
//! `EnrollmentRepository::get_enrollment_operation`, etc.) would check out
//! a SEPARATE pooled connection per call, and a reconciler running
//! concurrently on another connection could mutate a link or marker
//! between two such independent reads -- producing a snapshot that
//! describes a combination that never actually coexisted. `Deferred` fixes
//! the SQLite read snapshot at the first statement executed inside the
//! transaction and keeps it fixed (under WAL) regardless of what other
//! connections commit while this transaction is still open.

use std::sync::Arc;

use crate::recovery::{
    LocalObservation, LocalRecoveryEvidence, RecoveryDomain, RecoveryLocalSnapshot,
    RecoveryOperationKey,
};
use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::enrollment::{row_to_enrollment_operation, row_to_pending_enrollment};
use yadorilink_sync_sqlite::membership_operation::row_to_membership_operation;
use yadorilink_sync_sqlite::role_loss_operation::row_to_role_loss_operation_strict;

pub struct RecoverySnapshotReader {
    database: Arc<SyncDatabase>,
}

impl RecoverySnapshotReader {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Reads every piece of local recovery evidence for one
    /// `(domain, operation_id)` from a SINGLE SQLite read transaction --
    /// never by calling `get_enrollment_operation`/`list_links`/
    /// `get_membership_operation`/etc. independently. Read-only: never
    /// writes, never calls the coordination plane, never advances `attempts`
    /// or any other counter. See [`RecoveryLocalSnapshot`]'s own doc comment
    /// for what this distinguishes: an absent operation row
    /// (`OperationNotFound`), a present-but-corrupt one
    /// (`InvalidOperation`), and a genuine database read failure (`Err`) are
    /// three different things that must never be collapsed into each other.
    pub fn recovery_local_snapshot(
        &self,
        key: &RecoveryOperationKey,
    ) -> Result<RecoveryLocalSnapshot, SyncError> {
        // This is a genuinely read-only, multi-statement snapshot across
        // several tables -- `SyncDatabase::read` only checks out a plain
        // `&Connection` (no owned transaction), so a `Deferred` transaction
        // is opened directly on it via `unchecked_transaction` (the rusqlite
        // API for exactly this: a transaction built from a shared `&Connection`
        // reference rather than requiring `&mut`). It fixes the SQLite read
        // snapshot at its first statement and holds it for every domain
        // dispatch below, without taking `SyncDatabase`'s writer_gate --
        // unlike `write`/`write_immediate`, nothing here ever mutates state.
        self.database.read::<_, SyncError>(|conn| {
            let tx = conn.unchecked_transaction()?;
            let result = match key.domain {
                RecoveryDomain::Enrollment => Self::snapshot_enrollment_in_tx(&tx, key)?,
                RecoveryDomain::Membership => Self::snapshot_membership_in_tx(&tx, key)?,
                RecoveryDomain::RoleLoss => Self::snapshot_role_loss_in_tx(&tx, key)?,
            };
            tx.commit()?;
            Ok(result)
        })
    }

    fn snapshot_enrollment_in_tx(
        tx: &rusqlite::Transaction<'_>,
        key: &RecoveryOperationKey,
    ) -> Result<RecoveryLocalSnapshot, SyncError> {
        let decoded = {
            let mut stmt = tx.prepare(
                "SELECT operation_id, kind, group_id, group_name, device_id, local_path, \
                        storage_mode, state, last_error, attempts, created_at_unix, updated_at_unix \
                 FROM enrollment_operations WHERE operation_id = ?1",
            )?;
            let mut rows = stmt.query([key.operation_id.as_str()])?;
            match rows.next()? {
                None => None,
                Some(row) => {
                    let raw_state: Option<String> = row.get(7).ok();
                    Some((row_to_enrollment_operation(row), raw_state))
                }
            }
        };

        let operation = match decoded {
            None => {
                return Ok(RecoveryLocalSnapshot::OperationNotFound { key: key.clone() });
            }
            Some((Err(error), raw_state)) => {
                return Ok(RecoveryLocalSnapshot::InvalidOperation {
                    key: key.clone(),
                    raw_state,
                    detail: error.to_string(),
                });
            }
            Some((Ok(operation), _)) => operation,
        };

        // Always search by `local_path`, regardless of whether `group_id`
        // has resolved yet -- this snapshot reports whatever local evidence exists,
        // it does not decide what's expected for the operation's own
        // state. A `Create` row still `PreparePending` (no `group_id` yet)
        // can still have a live link sitting at its own `local_path` (e.g.
        // this path already belongs to a different group); skipping the
        // lookup would hide that link as `ConfirmedAbsent` instead of
        // surfacing it for the diagnosis layer to qualify.
        let link = Self::observe_link_by_path(tx, &operation.local_path)?;
        let pending_marker = Self::observe_pending_enrollment(tx, &operation.operation_id)?;

        Ok(RecoveryLocalSnapshot::Found(Box::new(LocalRecoveryEvidence::Enrollment(
            crate::recovery::EnrollmentLocalEvidence { operation, link, pending_marker },
        ))))
    }

    fn snapshot_membership_in_tx(
        tx: &rusqlite::Transaction<'_>,
        key: &RecoveryOperationKey,
    ) -> Result<RecoveryLocalSnapshot, SyncError> {
        let decoded = {
            let mut stmt = tx.prepare(
                "SELECT operation_id, action, commit_mode, removed_device_id, group_ids, \
                        target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                        last_error, created_at_unix, updated_at_unix \
                 FROM membership_operations WHERE operation_id = ?1",
            )?;
            let mut rows = stmt.query([key.operation_id.as_str()])?;
            match rows.next()? {
                None => None,
                Some(row) => {
                    let raw_state: Option<String> = row.get(7).ok();
                    Some((row_to_membership_operation(row), raw_state))
                }
            }
        };

        let operation = match decoded {
            None => {
                return Ok(RecoveryLocalSnapshot::OperationNotFound { key: key.clone() });
            }
            Some((Err(error), raw_state)) => {
                return Ok(RecoveryLocalSnapshot::InvalidOperation {
                    key: key.clone(),
                    raw_state,
                    detail: error.to_string(),
                });
            }
            Some((Ok(operation), _)) => operation,
        };

        // The union of both group-id sources this operation could latch --
        // sorted and deduplicated so the result never depends on row order
        // or which of the two lists a group happened to come from.
        let mut candidate_group_ids: Vec<String> =
            operation.group_ids.iter().chain(operation.latch_group_ids.iter()).cloned().collect();
        candidate_group_ids.sort();
        candidate_group_ids.dedup();

        let present_durability_latches = if candidate_group_ids.is_empty() {
            Vec::new()
        } else {
            let placeholders =
                candidate_group_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            let sql = format!(
                "SELECT group_id FROM durability_unknown_latches WHERE group_id IN ({placeholders}) \
                 ORDER BY group_id"
            );
            let mut stmt = tx.prepare(&sql)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(candidate_group_ids.iter()), |r| {
                    r.get::<_, String>(0)
                })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        Ok(RecoveryLocalSnapshot::Found(Box::new(LocalRecoveryEvidence::Membership(
            crate::recovery::MembershipLocalEvidence { operation, present_durability_latches },
        ))))
    }

    fn snapshot_role_loss_in_tx(
        tx: &rusqlite::Transaction<'_>,
        key: &RecoveryOperationKey,
    ) -> Result<RecoveryLocalSnapshot, SyncError> {
        let decoded = {
            let mut stmt = tx.prepare(
                "SELECT operation_id, group_id, source_device_id, target_device_id, lease_id, \
                        worker_membership_generation, action, state, local_path, attempts, \
                        created_at_unix, updated_at_unix \
                 FROM role_loss_operations WHERE operation_id = ?1",
            )?;
            let mut rows = stmt.query([key.operation_id.as_str()])?;
            match rows.next()? {
                None => None,
                Some(row) => {
                    let raw_state: Option<String> = row.get(7).ok();
                    Some((row_to_role_loss_operation_strict(row), raw_state))
                }
            }
        };

        let operation = match decoded {
            None => {
                return Ok(RecoveryLocalSnapshot::OperationNotFound { key: key.clone() });
            }
            Some((Err(error), raw_state)) => {
                return Ok(RecoveryLocalSnapshot::InvalidOperation {
                    key: key.clone(),
                    raw_state,
                    detail: error.to_string(),
                });
            }
            Some((Ok(operation), _)) => operation,
        };

        let link = match operation.local_path.as_deref() {
            Some(local_path) => Self::observe_link_by_path(tx, local_path)?,
            // No specific path recorded -- fall back to every live link for
            // this group; more than one candidate is `Ambiguous`, never
            // resolved by picking one arbitrarily.
            None => Self::observe_link_by_group(tx, &operation.group_id)?,
        };

        Ok(RecoveryLocalSnapshot::Found(Box::new(LocalRecoveryEvidence::RoleLoss(
            crate::recovery::RoleLossLocalEvidence { operation, link },
        ))))
    }

    /// Reads the `links` row at exactly this `local_path`, regardless of
    /// which `group_id` it actually names -- deliberately NOT filtered by
    /// the operation's own expected `group_id`. Filtering by both would
    /// report `ConfirmedAbsent` for a link that genuinely exists at this
    /// path but under a DIFFERENT group, hiding exactly the
    /// identity-conflicting link a diagnosis classifier
    /// most needs to see -- mirrors how `observe_pending_enrollment`
    /// deliberately keeps a marker whose other fields disagree with the
    /// operation instead of filtering it out.
    fn observe_link_by_path(
        tx: &rusqlite::Transaction<'_>,
        local_path: &str,
    ) -> Result<LocalObservation<crate::recovery::LocalLinkEvidence>, SyncError> {
        let mut stmt = tx.prepare(
            "SELECT local_path, group_id, paused, materialization_policy, orphaned, root_token \
             FROM links WHERE local_path = ?1",
        )?;
        let rows = stmt.query(rusqlite::params![local_path])?;
        Self::collect_local_link_evidence(rows)
    }

    fn observe_link_by_group(
        tx: &rusqlite::Transaction<'_>,
        group_id: &str,
    ) -> Result<LocalObservation<crate::recovery::LocalLinkEvidence>, SyncError> {
        let mut stmt = tx.prepare(
            "SELECT local_path, group_id, paused, materialization_policy, orphaned, root_token \
             FROM links WHERE group_id = ?1 ORDER BY local_path",
        )?;
        let rows = stmt.query(rusqlite::params![group_id])?;
        Self::collect_local_link_evidence(rows)
    }

    /// Steps through `rows` itself with `rusqlite::Rows::next`, not
    /// `Statement::query_map(...).collect()` -- the two error sources that
    /// call chain conflates must stay distinguishable. Advancing the
    /// cursor (`rows.next()?`) can fail for reasons that mean the DATABASE
    /// itself cannot be trusted right now (I/O, corruption, a broken
    /// connection) -- that must propagate as `Err(SyncError)`, the same as
    /// every other genuine read failure. Decoding a row that WAS
    /// successfully read (`row_to_local_link_evidence`) can fail for a
    /// completely different reason -- this one row's own shape is bad (e.g.
    /// an unrecognized `materialization_policy`) -- which is a
    /// `LocalObservation::Invalid`, not a database-wide failure. Folding
    /// both into one `Result` (as an earlier version of this function's
    /// `query_map(...).collect()` did) reported a real SQLite execution
    /// error the same way as a single corrupt row, which would make the
    /// diagnosis layer trust the REST of a database it cannot actually read.
    fn collect_local_link_evidence(
        mut rows: rusqlite::Rows<'_>,
    ) -> Result<LocalObservation<crate::recovery::LocalLinkEvidence>, SyncError> {
        let mut decoded = Vec::new();
        while let Some(row) = rows.next()? {
            match row_to_local_link_evidence(row) {
                Ok(link) => decoded.push(link),
                Err(error) => {
                    return Ok(LocalObservation::Invalid { detail: error.to_string() });
                }
            }
        }
        Ok(match decoded.len() {
            0 => LocalObservation::ConfirmedAbsent,
            1 => LocalObservation::Found(decoded.into_iter().next().expect("length checked above")),
            n => LocalObservation::Ambiguous { detail: format!("{n} candidate links") },
        })
    }

    fn observe_pending_enrollment(
        tx: &rusqlite::Transaction<'_>,
        operation_id: &str,
    ) -> Result<LocalObservation<crate::recovery::PendingEnrollmentEvidence>, SyncError> {
        let mut stmt = tx.prepare(
            "SELECT operation_id, kind, group_id, device_id, local_path \
             FROM pending_enrollments WHERE operation_id = ?1",
        )?;
        let mut rows = stmt.query([operation_id])?;
        Ok(match rows.next()? {
            None => LocalObservation::ConfirmedAbsent,
            Some(row) => match row_to_pending_enrollment(row) {
                Ok(marker) => LocalObservation::Found(crate::recovery::PendingEnrollmentEvidence {
                    operation_id: marker.operation_id,
                    kind: marker.kind,
                    group_id: marker.group_id,
                    device_id: marker.device_id,
                    local_path: marker.local_path,
                }),
                Err(error) => LocalObservation::Invalid { detail: error.to_string() },
            },
        })
    }
}

/// Strict decode for [`crate::recovery::LocalLinkEvidence`] -- unlike
/// `ReplicaCoordinator::link_repository().list_links()`'s
/// `MaterializationPolicy::from_db_str`, this never panics on an
/// unrecognized `materialization_policy` value: a recovery snapshot must
/// surface a corrupt link row as [`crate::recovery::LocalObservation::Invalid`],
/// never crash the daemon process trying to diagnose it.
pub(crate) fn row_to_local_link_evidence(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::recovery::LocalLinkEvidence> {
    let local_path: String = r.get(0)?;
    let group_id: String = r.get(1)?;
    let paused: i64 = r.get(2)?;
    let policy_raw: String = r.get(3)?;
    let orphaned: i64 = r.get(4)?;
    let root_token: Option<String> = r.get(5)?;
    let materialization_policy = match policy_raw.as_str() {
        "eager" => MaterializationPolicy::Eager,
        "ondemand" => MaterializationPolicy::OnDemand,
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown materialization policy: {other}"),
                )),
            ));
        }
    };
    Ok(crate::recovery::LocalLinkEvidence {
        group_id,
        local_path,
        materialization_policy,
        paused: paused != 0,
        orphaned: orphaned != 0,
        root_token_present: root_token.is_some(),
    })
}

#[cfg(test)]
mod tests;
