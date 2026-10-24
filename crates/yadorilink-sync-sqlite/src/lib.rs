//! The single adapter owning all YadoriLink-specific SQLite persistence:
//! application schema, repository SQL, row/domain-type mapping, and every
//! cross-table atomic transaction this application needs (both remote
//! change admission and the wider local-authoring commit span tables from
//! several domains, which is why these don't cleanly split into separate
//! crates by domain).
//!
//! Built on `yadorilink-sqlite-runtime`'s connection pool/writer-gate/
//! transaction mechanics, which knows nothing about this crate's schema or
//! domain types. Implements ports declared in `yadorilink-replica-engine`
//! without those port traits knowing this crate exists.
//!
//! Deliberately does NOT own: domain decision logic (whether a conflict
//! copy is required, which execution fence to bump, whether a
//! materialization job is needed) -- callers decide, this crate only
//! persists already-decided writes atomically.

pub mod author_incarnation;
pub mod content_write_open;
pub mod dag_store;
#[cfg(test)]
mod deferred_window_durability_tests;
pub mod desired_state;
pub mod dirty_path;
pub mod displacement_guard;
pub mod enrollment;
mod error;
pub mod exact_materialized_commit;
pub mod exclusive_open;
pub mod file_identity_codec;
pub mod file_index;
pub mod handoff_lease;
pub mod held_path;
pub mod link;
pub mod local_author;
pub mod local_capture_provenance;
pub mod materialization_basis;
mod materialization_intent_repository;
mod materialization_state;
pub mod materialized_generation;
pub mod membership_operation;
pub mod native_admission;
pub mod native_authoring;
pub mod native_bootstrap;
pub mod native_bootstrap_codec;
#[cfg(test)]
mod native_bulk_authoring_tests;
pub mod native_capture;
#[cfg(test)]
mod native_capture_profile_tests;
pub mod native_checkpoint_authorization;
pub mod native_checkpoint_frontier;
pub mod native_checkpoint_install;
pub mod native_closure;
pub mod native_contest_candidates;
pub mod native_desired_state;
pub mod native_history_floor;
#[cfg(test)]
mod native_prepare_count_tests;
pub mod native_publication;
pub mod native_rebootstrap;
pub mod native_rebootstrap_install;
pub mod native_rebootstrap_recovery;
pub mod native_rebootstrap_replay;
pub mod native_rebootstrap_retained;
pub mod native_rebootstrap_target;
pub mod native_recovery_items;
pub mod native_recursive_operation;
pub mod native_replication;
#[cfg(test)]
mod native_scaling_tests;
pub mod native_store;
#[cfg(test)]
mod native_store_reference;
pub mod native_summary_cache;
#[cfg(test)]
mod native_summary_scaling_tests;
mod new_path_rows;
#[cfg(test)]
mod new_path_rows_tests;
mod new_path_settlement;
#[cfg(test)]
mod new_path_settlement_tests;
pub mod offline_group_policy_log;
pub mod offline_peer_authorization;
pub mod paused_items;
pub mod pinned_items;
pub mod policy_watermark;
pub mod projection_obligations;
pub mod provider;
pub mod provider_enumerate;
pub mod provider_projector;
pub mod provider_provenance;
pub mod provider_write;
pub mod remote_custody_hold;
pub mod remote_custody_lease;
mod replica_schema;
pub mod replica_tables;
pub mod restore_operation;
pub mod rewind_commit;
pub mod rewind_plan;
pub mod rewind_run;
pub mod role_loss_operation;
mod store;
pub mod structural_origin;
#[cfg(test)]
mod test_alloc;
mod types;
#[cfg(test)]
mod windows_durability_harness;

pub use dirty_path::DirtyPathRepository;
pub use enrollment::EnrollmentRepository;
pub use error::SyncSqliteError;
pub use handoff_lease::HandoffLeaseRepository;
pub use held_path::HeldPathRepository;
pub use materialization_intent_repository::{
    clear_flush_pending_in_tx, flush_pending_proof_identity, write_landed_unproven,
    IntentDisposition, MaterializationIntentRepository, MaterializationTempLedger,
    TempReleaseQueue,
};
#[cfg(any(test, feature = "test-support"))]
pub use materialization_state::{fail_placeholder_reads_for_path, fail_state_reads_for_path};
pub use materialization_state::{
    ContentHash, MaterializationCounts, MaterializationStateRepository,
    RecordedPlaceholderGeneration,
};
pub use membership_operation::MembershipOperationRepository;
pub use offline_group_policy_log::{OfflineGroupPolicyLog, OfflineGroupPolicyLogRepository};
pub use offline_peer_authorization::{
    OfflinePeerAuthorization, OfflinePeerAuthorizationRepository, OfflineSnapshotVersions,
};
pub use paused_items::PausedItemRepository;
pub use pinned_items::{PinnedItemRepository, Retention, RetentionPolicy};
pub use policy_watermark::{PolicyWatermark, PolicyWatermarkRepository};
pub use remote_custody_hold::RemoteCustodyHoldRepository;
pub use remote_custody_lease::RemoteCustodyLeaseRepository;
pub use replica_schema::{init_replica_schema, ReplicaSchemaError};
pub use restore_operation::RestoreOperationRepository;
pub use rewind_run::{RewindRunRepository, RewindRunStart};
pub use role_loss_operation::RoleLossOperationRepository;

/// A plain duplicate rather than a shared cross-crate helper: five lines,
/// no state, not worth its own module.
pub(crate) fn read_inventory_operation_id(
    row: &rusqlite::Row<'_>,
    column: usize,
) -> rusqlite::Result<Option<String>> {
    match row.get_ref(column)? {
        rusqlite::types::ValueRef::Text(bytes) => {
            Ok(std::str::from_utf8(bytes).ok().map(str::to_owned))
        }
        _ => Ok(None),
    }
}
pub use store::{read_canonical_current_row, CanonicalCurrentRow, SqliteSyncStore};
pub use types::{CurrentVersionSnapshot, RetainedVersion, RetainedVersionState};
