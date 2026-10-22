//! Physical content-addressed block *reclamation*: custody-scoped deletion
//! of the blocks an eviction freed. Owned by `ReplicaCoordinator` because
//! the decision is a read across the file index, the materialization state
//! and the block-reference set, all of which this type already holds.

use yadorilink_filesystem_sync::block_liveness::BlockPhysicalDeletionGuard;
use yadorilink_local_storage::{BlockReclamationStore, GcReport};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::custody::VerifiedCustody;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::ReplicaCoordinator;

impl ReplicaCoordinator {
    /// Reclaims the cached blocks of a path whose eviction custody has been
    /// verified. The caller must already hold the exclusive
    /// `BlockPhysicalDeletionGuard`; every safety-relevant re-check (the
    /// custody's exact version, pin and materialization state, the custody
    /// confirmation itself, and the cross-row reference set) runs here,
    /// under that guard, in this order.
    pub(crate) fn reclaim_cached_blocks(
        &self,
        _guard: &BlockPhysicalDeletionGuard<'_>,
        custody: VerifiedCustody<'_>,
        siblings: &[VerifiedCustody<'_>],
        store: &dyn BlockReclamationStore,
    ) -> Result<GcReport, SyncSqliteError> {
        let Some(current) =
            self.sqlite().dag_get_current_version_record(custody.group_id(), custody.path())?
        else {
            return Ok(GcReport::default());
        };
        if current.deleted {
            return Ok(GcReport::default());
        }
        let current = current.to_file_version();
        if current.version_hash != *custody.version_hash() || current.blocks != custody.blocks() {
            return Ok(GcReport::default());
        }
        // Custody confirmation may have waited on the network. Revalidate
        // local retention requirements under the exclusive deletion guard so
        // a concurrent re-hydration cannot be followed by reclaiming the
        // blocks its final state requires.
        if self
            .materialization_state_repository()
            .get_materialization_state(custody.group_id(), custody.path())?
            != Some(MaterializationState::Remote)
        {
            return Ok(GcReport::default());
        }
        // A path the user asked to keep on this device keeps its cached blocks too, even when
        // the pin landed after the lease was taken. A policy that cannot be read frees nothing.
        if self.pinned_item_repository().retention(custody.group_id(), custody.path())?.policy
            == yadorilink_sync_sqlite::RetentionPolicy::Pinned
        {
            return Ok(GcReport::default());
        }
        if !custody.confirmation_still_valid() {
            return Ok(GcReport::default());
        }

        // Placeholders sharing these blocks whose own custody is confirmed stop rooting them
        // (otherwise the last of several identical evicted files never frees anything,
        // and GC cannot either, since a current row roots its blocks). Each one is
        // re-validated here, under the guard, exactly like the file itself; one that no longer
        // qualifies stays a reference.
        let mut custodied_siblings = Vec::new();
        for sibling in siblings {
            // A group that became a full replica since the custody was taken is the durable
            // holder again: its placeholders keep their blocks. An unreadable policy keeps them.
            if !matches!(
                self.link_repository().materialization_policy_for_group(sibling.group_id()),
                Ok(None
                    | Some(
                        yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand
                    ))
            ) {
                continue;
            }
            let Some(row) =
                self.sqlite().dag_get_current_version_record(sibling.group_id(), sibling.path())?
            else {
                continue;
            };
            let row = row.to_file_version();
            if row.version_hash != *sibling.version_hash()
                || row.blocks != sibling.blocks()
                || self
                    .materialization_state_repository()
                    .get_materialization_state(sibling.group_id(), sibling.path())?
                    != Some(MaterializationState::Remote)
                || self
                    .pinned_item_repository()
                    .retention(sibling.group_id(), sibling.path())?
                    .policy
                    == yadorilink_sync_sqlite::RetentionPolicy::Pinned
                || !sibling.confirmation_still_valid()
            {
                continue;
            }
            custodied_siblings.push((
                sibling.group_id().to_owned(),
                sibling.path().to_owned(),
                *sibling.version_hash(),
            ));
        }
        let needed =
            self.materialization_state_repository().blocks_referenced_outside_current_file(
                custody.group_id(),
                custody.path(),
                custody.version_hash(),
                &custodied_siblings,
            )?;
        let reclaimable: Vec<String> = current
            .blocks
            .iter()
            .map(|block| hex::encode(&block.hash.0))
            .filter(|hash| !needed.contains(hash))
            .collect();
        Ok(store.reclaim_cached_blocks(&reclaimable)?)
    }
}
