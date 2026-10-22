use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::MaterializationState;

use super::super::types::*;
use super::MaterializationPlan;

impl super::super::LocalConvergenceExecutor {
    /// The symlink lane of [`Self::materialize_local`]: a payload that IS a
    /// symlink carries no content blocks at all.
    pub(super) fn materialize_symlink_lane(
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
        // The same last line of defence the content, placeholder and
        // tombstone lanes have: creating the link renames it over whatever
        // is at the path, which destroys a file edited since capture last
        // looked. Decline and retry; once captured, the edit meets this
        // symlink as a concurrent change instead of vanishing. A link
        // already holding the payload's target has nothing to replace.
        let out_path = self.local_file_path(group_id, &record.path)?;
        let already_this_link =
            payload.version().meta.symlink_target.as_deref().is_some_and(|target| {
                std::fs::read_link(&out_path).is_ok_and(|on_disk| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::ffi::OsStrExt as _;
                        on_disk.as_os_str().as_bytes() == target
                    }
                    #[cfg(not(unix))]
                    {
                        on_disk.to_string_lossy().as_bytes() == target
                    }
                })
            });
        if !already_this_link
            && self.removal_would_destroy_unrecorded_state(group_id, &record.path, &out_path)?
        {
            tracing::info!(
                group_id,
                path = %record.path,
                "declining a symlink whose target holds local state this device has not \
                 captured yet; replacing it would destroy it silently"
            );
            return Ok(MaterializeResult::RetryRequired.into());
        }
        // A path that's no longer hazardous (e.g. a previously
        // colliding sibling was itself renamed/removed since the last
        // time this path was reconciled) must not keep a stale held
        // entry once it actually materializes normally again.
        //
        // Only an actual transition OUT of a hold opens an intent: this
        // whole branch runs on EVERY symlink materialize (the ordinary
        // case, not just a held one), and on Windows-without-symlink-opt-in
        // every one of those retries forever on the same capped backoff --
        // opening (and idempotently re-upserting) this extra intent
        // unconditionally on every single retry, for a path that was never
        // actually held, is a real, avoidable write on a path this codebase
        // already measures the cost of seriously elsewhere (see the
        // writer-gate cost discussion near this crate's no-op-write
        // instrumentation), and breaks the intent repository's own
        // documented "empty in steady state" invariant for good. Same
        // reasoning and gating as `hydration::hydrate_inner`'s
        // identical `was_held` check.
        //
        // When it was held, the intent is opened BEFORE the hold is
        // cleared, not after: a held row is `Remote` with
        // `held_reason` set -- the SET `held_reason` is itself what
        // protects it from the tombstone loop while held. The instant the
        // hold clears, the row looks like an ordinary, unprotected
        // `Remote` row until `materialize_symlink_at` either writes
        // the symlink and opens its own intent, or (a `PolicySkipped`
        // outcome -- no recorded target, or Windows-without-opt-in) opens
        // no intent at all and just returns. Without this guard, a
        // `PolicySkipped` exit -- or any transient failure
        // `materialize_symlink_at` itself could raise before reaching its
        // own intent-guard open -- lands the row at `Remote`,
        // `held_reason` NULL, no intent, and (this row never carries a
        // projection obligation once hazard settlement deleted it) no
        // obligation either: none of the tombstone loop's three vetoes.
        // Idempotent with whatever `materialize_symlink_at` opens next for
        // the same target (see `MaterializationIntentRepository::begin_
        // materialization_intent`'s own upsert semantics) -- this is not a
        // race with it, just closing the gap before it.
        // `intent_target_hash(&[])` mirrors the tombstone-delete path's own
        // sentinel for "no content to name yet" when no target is recorded
        // at all. Intentionally never consumed explicitly (no `.clear()`
        // call): held until this whole function returns, at which point it
        // drops without clearing -- exactly the fail-safe "leave the intent
        // dangling" outcome this guard exists to guarantee for a
        // `PolicySkipped`/failure exit. `materialize_symlink_at`'s own
        // success path clears the SAME underlying row via its own,
        // separately-opened guard.
        //
        // The payload's target, so this intent names the same object
        // `materialize_symlink_at` is about to open its own intent for and
        // write.
        let pre_clear_hold_intent_target = payload
            .version()
            .meta
            .symlink_target
            .as_deref()
            .map(yadorilink_local_storage::intent_target_hash_for_bytes)
            .unwrap_or_else(|| yadorilink_local_storage::intent_target_hash(&[]));
        let _pre_clear_hold_intent_guard = self.state.release_symlink_hold_under_intent(
            group_id,
            &record.path,
            &pre_clear_hold_intent_target,
            root_commit_permit,
        )?;
        let windows_opt_in = self.state.windows_symlink_opt_in_for_group(group_id)?;
        // `materialize_symlink_at` itself bumps the mutation fence,
        // immediately before the real symlink-creation syscall, ONLY
        // when it is actually about to write something -- this call
        // site must not bump unconditionally BEFORE even knowing
        // whether a write would happen, which would keep advancing
        // the generation on every retry of a permanently-skipped
        // symlink with no mutation ever occurring. See
        // `SymlinkMaterializeOutcome::WrittenExact`'s own doc
        // comment.
        let symlink_outcome = materialize_symlink_at(
            SymlinkMaterialization {
                state: self.state.as_ref(),
                root: &self.sync_root(group_id)?,
                group_id,
                windows_opt_in,
                origin_device_id,
                authoring,
                permit: root_commit_permit,
            },
            record,
            payload.version(),
        )?;
        // Proceeding to `ExactObject` on any `Ok(())` would promote a
        // policy skip (no recorded target, or a Windows peer that has
        // not opted in) to a claimed exact physical write. Only a genuine on-disk
        // write may settle as exact; a skip maps to `RetryRequired`
        // below, which is the ordinary capped-backoff retry path (see
        // `SymlinkMaterializeOutcome::PolicySkipped`'s own doc comment)
        // -- it re-examines this condition on its own schedule rather
        // than needing a dedicated liveness sweep, since the backoff is
        // capped and the obligation row is never deleted.
        match symlink_outcome {
            SymlinkMaterializeOutcome::WrittenExact { mutation_generation, written } => {
                match self.exact_object_evidence_after_write(
                    group_id,
                    &record.path,
                    RecordKind::Symlink,
                    &written,
                    mutation_generation,
                    // A symlink version carries no replicated xattrs; the
                    // gate only applies to regular files.
                    &super::super::types::XattrEvidence::ReproveFromDisk,
                )? {
                    Some(evidence) => Ok(MaterializeResult::Settled(evidence).into()),
                    None => Ok(MaterializeResult::RetryRequired.into()),
                }
            }
            SymlinkMaterializeOutcome::PolicySkipped => {
                // A policy-skipped
                // symlink row was left at `materialization_state`'s
                // schema default of `Present` (the row commit inside
                // `materialize_symlink_at` never demotes it, unlike
                // the analogous Placeholder pattern used for a
                // not-fully-fetched regular file just below). A
                // `Present` row with nothing physically on disk and
                // no materialization intent is exactly what the
                // periodic repair sweep (`repair_interrupted_
                // materializations`) reads as an offline deletion --
                // which it then journals dirty and the always-running
                // dirty-journal redrive turns into a real, signed,
                // GROUP-WIDE PROPAGATING tombstone `Change`, deleting
                // this path from every peer even though the policy
                // skip was meant to be a benign, local-only decision.
                // Demoting to `Remote` here (mirroring the
                // regular-file "not really materialized yet" pattern)
                // keeps the repair sweep's own `materialization_state
                // != Hydrated` pre-filter from ever examining this row
                // in the first place. See `repair_one_interrupted_
                // symlink`'s matching policy check for the
                // defense-in-depth half of this fix, covering a
                // legacy row already stuck at `Present` before this
                // retry has a chance to correct it.
                self.state.set_materialization_state(
                    group_id,
                    &record.path,
                    MaterializationState::Remote,
                    root_commit_permit,
                )?;
                Ok(MaterializeResult::RetryRequired.into())
            }
            SymlinkMaterializeOutcome::CommitRejected => {
                // Deliberately NOT the `Remote` demotion above.
                // A real symlink was written here; only the record of
                // it was refused. Demoting would tell the repair
                // sweep this path holds no content while it actually
                // does, and the retry re-drives the write anyway. The
                // row keeps whatever state it had -- the refused
                // commit changed nothing -- and the still-open
                // materialization intent records that a write
                // happened.
                Ok(MaterializeResult::RetryRequired.into())
            }
        }
    }
}
