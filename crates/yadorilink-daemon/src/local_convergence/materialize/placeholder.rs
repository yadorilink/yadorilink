use std::path::Path;

use yadorilink_local_storage::create_or_defer_placeholder;
use yadorilink_peer_session::PeerSessionError;

use super::MaterializationPlan;

impl super::super::LocalConvergenceExecutor {
    /// The step every lane that records a version without its content
    /// shares: verify the target and, where nothing stands at the path, bump
    /// its mutation fence under `fence_reason` and give a native provider
    /// (Windows `cfapi-host.exe`) its identity to create the object from,
    /// recording it. Where an object stands (`object_present`) nothing is
    /// done at all: it is left exactly as it is, it keeps the proof it
    /// carries (evidence that it is the daemon's own untouched write), and no
    /// provider creation is owed or deferred. Nothing is ever written to the
    /// user tree here. Returns whether the object's creation was deferred to
    /// a separate process, in which case nothing is on disk under this name
    /// yet.
    pub(super) fn place_provider_object(
        &self,
        plan: &MaterializationPlan<'_>,
        out_path: &Path,
        object_present: bool,
        fence_reason: &'static str,
    ) -> Result<bool, PeerSessionError> {
        let MaterializationPlan { group_id, record, permit: root_commit_permit, .. } = *plan;
        self.verify_write_target(group_id, out_path)?;
        // A provider creates an object where none stands. Where one already
        // does, there is nothing to create and so nothing to defer to the
        // provider (which skips an occupied path anyway); deferring would
        // leave the lane retrying forever.
        if object_present {
            return Ok(false);
        }
        let outcome = create_or_defer_placeholder(out_path);
        let deferred = outcome.is_deferred_to_a_separate_process();
        self.state.dag_bump_mutation_fence(group_id, &record.path, fence_reason)?;
        self.state
            .record_placeholder_identity(group_id, &record.path, outcome, root_commit_permit)
            .map_err(PeerSessionError::from)?;
        Ok(deferred)
    }
}
