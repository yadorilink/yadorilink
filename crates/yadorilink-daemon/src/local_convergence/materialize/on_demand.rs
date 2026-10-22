use yadorilink_peer_session::PeerSessionError;

use super::super::types::*;
use super::MaterializationPlan;

impl super::super::LocalConvergenceExecutor {
    /// The on-demand lane of [`Self::materialize_local`]: an OnDemand
    /// record is recorded without its content and no block fetch at all.
    pub(super) fn materialize_on_demand_lane(
        &self,
        plan: &MaterializationPlan<'_>,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        let MaterializationPlan { group_id, record, permit: root_commit_permit, .. } = *plan;
        // A hazardous record is held: no on-disk artifact under this name at
        // all, and never any alternate name.
        if let Some(reason) = &plan.hazard_reason {
            return self.hold_for_hazard(plan, reason);
        }
        // Nothing is written at the path, but the version this row now
        // names is not the one any object there was fetched for, so the
        // lane's last-line disk check stands here as it does for the eager
        // lane: an unauthored local edit is left for capture to take first,
        // before the row is persisted or an intent opened, so a decline
        // leaves nothing behind.
        let out_path = self.local_file_path(group_id, &record.path)?;
        if self.disk_holds_uncaptured_local_bytes(
            group_id,
            &record.path,
            &out_path,
            Some(&record.blocks),
        )? {
            tracing::info!(
                group_id,
                path = %record.path,
                "declining to record an on-demand version over a target that no longer matches \
                 this device's indexed content; an unauthored local edit is on disk"
            );
            yadorilink_peer_session::dst_trace(&record.path, || {
                format!(
                    "on-demand record DECLINED on {}: on-disk bytes diverge from indexed \
                     content -- unauthored local edit protected",
                    self.local_device_id
                )
            });
            return Ok(MaterializeResult::RetryRequired.into());
        }
        // OnDemand: no block fetch at all -- the point of an on-demand
        // device is deferring that until the item is opened.
        //
        // The same journaled-write seam the eager branches use: this is the
        // ORDINARY on-demand-receive path, the one a plain on-demand device
        // takes for every incoming file. The row is committed before the
        // path settles, and a crash/restart in between must not leave an
        // indexed, not-deleted row with no protection at all.
        let object_present = std::fs::symlink_metadata(&out_path).is_ok();
        let intent_guard = self.state.open_remote_write(
            group_id,
            record,
            plan.origin_device_id,
            plan.authoring,
            &plan.columns,
            &|| self.root_lease_for(group_id),
            object_present,
            root_commit_permit,
        )?;
        // Nothing is written, so an object already at the path keeps the
        // proof it carries (it is still the daemon's own untouched write,
        // whichever version the row now names); the evidence this settles as
        // (`PolicyRemote`) carries no fence value of its own (it is never
        // CAS-published).
        let provider_deferred =
            self.place_provider_object(plan, &out_path, object_present, "ondemand_remote_record")?;
        if provider_deferred {
            // Windows: the provider object is created later by
            // `cfapi-host.exe`'s own poll, not by this call. This is NOT a
            // settled outcome: settling `PolicyRemote` completes this path's
            // projection obligation, and clearing the intent removes the
            // protection of a path that genuinely has nothing under its own
            // name yet. Left open deliberately (no mechanism in this
            // codebase yet observes `cfapi-host.exe`'s own confirmation),
            // and retried: a fresh `materialize` call for this path is
            // idempotent here (`RecordIfAbsent`'s persist discipline never
            // overwrites a generation already in use).
            return Ok(MaterializeResult::RetryRequired.into());
        }
        // This IS a settled outcome: on-demand policy deliberately defers
        // content until access. The row is `Remote` (nothing at the path)
        // or `Present` (an object that was already there is left untouched),
        // so the intent has nothing left to protect and is cleared. No mode
        // or attributes are applied: this lane places no object.
        intent_guard.clear()?;
        Ok(MaterializeResult::Settled(SettlementEvidence::PolicyRemote).into())
    }
}
