use yadorilink_local_storage::{apply_unix_mode, create_explicit_directory};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::RecordKind;

use super::super::types::*;
use super::MaterializationPlan;

impl super::super::LocalConvergenceExecutor {
    /// The directory lane of [`Self::materialize_local`]: a payload that IS
    /// a directory has no content, so it is neither fetched nor deferred
    /// to a placeholder under any policy. It is created as a real
    /// directory -- its missing ancestors structurally, through the
    /// recording `mkdir` helper; itself not, since it is the replicated
    /// entry -- given its mode, and settled exact.
    ///
    /// A directory already at the path is kept as it is, contents and all;
    /// only its mode is applied. Anything else at the path (a file, a
    /// symlink) is left untouched and the attempt fails, to be retried.
    pub(super) fn materialize_directory_lane(
        &self,
        plan: &MaterializationPlan<'_>,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        let MaterializationPlan {
            group_id,
            payload,
            record,
            origin_device_id,
            authoring,
            permit: root_commit_permit,
            ..
        } = *plan;
        if let Some(reason) = &plan.hazard_reason {
            return self.hold_for_hazard(plan, reason);
        }
        // A path that was held and no longer is: release the hold under an
        // intent, so the row is never unprotected between the two -- the
        // same step the symlink lane takes, for the same reason.
        let _pre_clear_hold_intent_guard = self.state.release_symlink_hold_under_intent(
            group_id,
            &record.path,
            &yadorilink_local_storage::intent_target_hash(&[]),
            root_commit_permit,
        )?;
        let raw_root = self.sync_root(group_id)?;
        self.state.verify_root(&raw_root, group_id)?;
        let canonical_root = self
            .canonical_sync_root(group_id, &raw_root)
            .ok_or_else(|| PeerSessionError::PathEscapesRoot(raw_root.display().to_string()))?;
        let out_path = raw_root.join(&record.path);
        let written = payload.version();

        let (mutation_generation, intent_guard) = self.state.open_directory_write(
            group_id,
            record,
            origin_device_id,
            authoring,
            &plan.columns,
            root_commit_permit,
        )?;
        create_explicit_directory(&out_path, &canonical_root, &self.structural_ledger(group_id))?;
        apply_unix_mode(&out_path, written.meta.unix_mode)?;
        // The commit clears the intent; dropping the guard uncleared is
        // inert, and on a refused commit it is what keeps the intent open.
        drop(intent_guard);
        if !self.state.settle_directory_write(
            group_id,
            &record.path,
            &out_path,
            written.version_hash,
            mutation_generation,
            root_commit_permit,
        )? {
            return Ok(MaterializeResult::RetryRequired.into());
        }
        match self.exact_object_evidence_after_write(
            group_id,
            &record.path,
            RecordKind::Directory,
            written,
            mutation_generation,
            &super::super::types::XattrEvidence::ReproveFromDisk,
        )? {
            Some(evidence) => Ok(MaterializeResult::Settled(evidence).into()),
            None => Ok(MaterializeResult::RetryRequired.into()),
        }
    }
}
