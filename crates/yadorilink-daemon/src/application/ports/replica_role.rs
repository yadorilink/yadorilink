//! Replica-role's own ports -- what `ReplicaRoleService` needs from durable
//! storage, an established peer session, the coordination plane, and the
//! local link-watcher runtime, expressed as `dyn`-safe traits. Split into
//! five narrow ports rather than one wide one, mirroring Membership's own
//! split: each has an independent reason to vary (a fake lease port for
//! readiness-gate tests never needs a fake link-watcher runtime too).

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_domain::session_state::{
    FolderLink, RoleLossAction, RoleLossOperation, RoleLossOperationState,
};

use super::common::BoxFuture;
use crate::application::model::{RoleLossCommitOutcome, RoleLossCompensationOutcome};
use crate::handoff_proof::StrongHandoffProof;

/// The durable link-table reads/writes `ReplicaRoleService` needs.
/// Deliberately narrow: only the specific atomic transitions the
/// storage-mode/unlink sagas actually perform.
pub(crate) trait ReplicaRoleRepository: Send + Sync {
    fn list_links(&self) -> Result<Vec<FolderLink>, SyncError>;

    fn live_link_key_for_group(&self, group_id: &str) -> Result<Option<String>, SyncError>;

    /// Atomically re-enumerates the group's durability-root digest and, only
    /// if it still equals `expected_digest`, flips `local_path`'s
    /// materialization policy. `Ok(false)` means the digest had moved --
    /// the caller must treat this the same as an unconfirmed peer.
    fn recheck_digest_then_set_materialization_policy(
        &self,
        group_id: &str,
        local_path: &str,
        policy: MaterializationPolicy,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncError>;

    /// Same atomicity as `recheck_digest_then_set_materialization_policy`,
    /// for a link removal instead of a policy flip.
    fn recheck_digest_then_remove_link(
        &self,
        group_id: &str,
        local_path: &str,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncError>;

    /// Removes the link at `local_path` only if it still belongs to `group_id`,
    /// checked in the same transaction as the removal; otherwise
    /// `SyncError::GroupMismatch` and the link stays.
    fn remove_link_expecting_group(
        &self,
        local_path: &str,
        group_id: &str,
    ) -> Result<(), SyncError>;

    fn set_materialization_policy(
        &self,
        local_path: &str,
        policy: MaterializationPolicy,
    ) -> Result<(), SyncError>;

    /// Marks a group's local durability status as unknown -- the backstop a
    /// `--force` override latches so the UI cannot keep reporting the group
    /// healthy after an override that may have discarded its only complete
    /// copy.
    fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError>;

    /// Legacy duplicate-root recovery: arms additive-scan protection for
    /// every OTHER live link in `group_id` before a departing link's removal
    /// commits, so a crash after the removal can never leave a survivor
    /// whose first scan tombstones files that only existed under the
    /// departed root.
    fn arm_duplicate_recovery_paths(&self, group_id: &str) -> Result<(), SyncError>;

    fn set_suppress_tombstones(&self, local_path: &str, suppress: bool) -> Result<(), SyncError>;
}

/// The durable role-loss journal `ReplicaRoleService` uses to make a
/// coordination-plane handoff commit crash-safe -- see
/// `DaemonState::open_role_loss_operation`'s own doc comment for the
/// Prepared-before-commit ordering this exists to guarantee.
pub(crate) trait RoleLossJournal: Send + Sync {
    fn open_operation(
        &self,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
        action: RoleLossAction,
        local_path: &str,
    ) -> Result<String, String>;

    fn mark_worker_committed(&self, operation_id: &str, membership_generation: i64);

    fn discard_operation(&self, operation_id: &str);

    fn settle_success(&self, operation_id: &str);

    fn get_operation(&self, operation_id: &str) -> Result<Option<RoleLossOperation>, String>;

    fn list_operations_in_states(
        &self,
        states: &[RoleLossOperationState],
    ) -> Result<Vec<RoleLossOperation>, String>;

    /// Moves a row to `state`, stamping the current time.
    fn advance_operation(
        &self,
        operation_id: &str,
        state: RoleLossOperationState,
    ) -> Result<(), String>;

    /// Records one more compensation attempt and returns the new count.
    fn increment_attempts(&self, operation_id: &str) -> Result<i64, String>;

    fn delete_operation(&self, operation_id: &str) -> Result<(), String>;
}

/// Confirms another full replica is ready to take over a group, and obtains
/// the live, peer-attested lease a role-loss commit requires once a real
/// target is confirmed.
pub(crate) trait HandoffReadinessPort: Send + Sync {
    fn is_local_full_replica(&self, group_id: &str) -> bool;

    /// Takes a fresh whole-group durability proof against one named peer.
    ///
    /// Deliberately returns the proof value rather than a digest/device-id
    /// pair: a role-loss gate must be unable to satisfy itself with anything
    /// it merely remembers, and the only way to hold a
    /// [`StrongHandoffProof`] is to have just taken one. Cached background
    /// custody evidence is a different type and is not accepted here.
    fn full_replica_handoff_proof<'a>(
        &'a self,
        group_id: &'a str,
    ) -> BoxFuture<'a, Option<StrongHandoffProof>>;

    /// `None` means no live lease could be obtained (peer unreachable,
    /// refused, or its attested root digest didn't match this device's
    /// own) -- a lease is mandatory for a non-empty root set, so its
    /// absence refuses the whole role-loss commit.
    fn obtain_handoff_lease_from_peer<'a>(
        &'a self,
        group_id: &'a str,
        target_peer_device_id: &'a str,
        my_digest: [u8; 32],
    ) -> BoxFuture<'a, Option<String>>;
}

/// The coordination-plane HTTP calls a role-loss/storage-mode change needs.
pub(crate) trait RoleLossCoordination: Send + Sync {
    /// Whether this device currently has a coordination-plane address/
    /// access token recorded.
    fn is_configured(&self) -> bool;

    #[allow(clippy::too_many_arguments)]
    fn commit_handoff_role_loss<'a>(
        &'a self,
        group_id: &'a str,
        source_device_id: &'a str,
        target_device_id: &'a str,
        lease_id: Option<&'a str>,
        action: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, RoleLossCommitOutcome>;

    fn set_storage_mode<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        mode: &'a str,
    ) -> BoxFuture<'a, Result<(), String>>;

    /// Reverts a committed role loss on the coordination plane, restoring
    /// the source device's `eager` storage mode. Carries only identities,
    /// the lease and the expected membership generation -- never any
    /// digest, path or version content.
    fn compensate_handoff_role_loss<'a>(
        &'a self,
        group_id: &'a str,
        source_device_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
        expected_membership_generation: Option<i64>,
    ) -> BoxFuture<'a, Result<RoleLossCompensationOutcome, String>>;
}

/// The local link-watcher runtime a duplicate-root recovery restart and an
/// unlink both touch.
pub(crate) trait LinkRuntimePort: Send + Sync {
    fn start_link_watch(&self, local_path: String, group_id: String) -> Result<(), String>;

    fn stop_link_watch<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()>;
}

/// A port so a test can inject a fixed answer deterministically per daemon: the async task that calls
/// `set_storage_mode` is not guaranteed to run on the OS thread a test set a thread-local from.
pub(crate) trait OnDemandCapabilityPort: Send + Sync {
    fn allows_on_demand(&self, group_id: &str) -> bool;
}

/// The custody leases this device holds for other devices, at the moments it
/// gives up being a group's full replica.
pub(crate) trait CustodyLeaseHandoffPort: Send + Sync {
    /// Stops taking new leases for the group and moves every lease it holds
    /// to another full replica. `Ok` keeps the group closed to new leases
    /// until the returned guard is dropped; `Err` is the refusal to show the
    /// user (some lease has nowhere to go yet), and the role must not be lost.
    fn hand_off_leases<'a>(
        &'a self,
        group_id: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn Send>, String>>;
}
