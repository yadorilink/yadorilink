use std::path::Path;

use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use super::types::*;

mod directory;
mod eager;
mod on_demand;
mod placeholder;
mod symlink;

/// What every lane of [`LocalConvergenceExecutor::materialize_local`] works
/// from, established by its admission checks: the payload being installed,
/// who authored it, the hazard answer computed once for every lane, and the
/// root-commit permit this whole call holds.
///
/// Only [`LocalConvergenceExecutor::admit_materialization`] builds one, so
/// holding a plan means the root was verified and the path passed the
/// reserved-namespace and portability checks on this pass.
///
/// [`LocalConvergenceExecutor::materialize_local`]: super::LocalConvergenceExecutor::materialize_local
/// [`LocalConvergenceExecutor::admit_materialization`]: super::LocalConvergenceExecutor::admit_materialization
struct MaterializationPlan<'a> {
    group_id: &'a str,
    payload: &'a MaterializationPayload,
    record: &'a FileRecord,
    origin_device_id: &'a str,
    authoring: Option<&'a yadorilink_replica_domain::native_plan::NativeRowIdentity>,
    /// The metadata columns of the payload's version: what the row this
    /// attempt inserts shows. Written with that row, never ahead of it.
    columns: yadorilink_replica_domain::session_state::LocalFileMetaColumns,
    satisfied: Option<&'a BlockRequirement>,
    hazard_reason: Option<String>,
    permit: &'a RootCommitPermit<'a>,
    /// The obligation engine's claim on this path, when this attempt was
    /// handed one. The eager content write closes the obligation under it in
    /// the same transaction as its proof.
    claim: Option<super::obligation_claims::PathClaim<'a>>,
}

impl MaterializationPlan<'_> {
    /// Applies the owner-executable bit and xattrs this payload specifies to
    /// `out_path`. Every lane reads them from the payload, never the row:
    /// what a materialization applies is decided by its payload alone.
    ///
    /// Returns the attempt's own strict xattr check, taken before the final
    /// mode was applied, for the exactness gate that follows.
    fn apply_payload_metadata(
        &self,
        out_path: &Path,
    ) -> Result<super::types::XattrEvidence, PeerSessionError> {
        let applied = yadorilink_local_storage::apply_file_metadata_verified(
            out_path,
            self.payload.version().meta.unix_mode,
            &self.payload.version().meta.xattrs,
        )?;
        Ok(super::types::XattrEvidence::from(applied))
    }
}

impl super::LocalConvergenceExecutor {
    /// Materialize `record` at its path, as far as this device can get on its
    /// own.
    ///
    /// This is the local half. It reads and writes this device's disk, index
    /// and native state, and it never talks to a peer: if the record names content this
    /// device does not hold, it stops and says so ([`LocalMaterializeOutcome::
    /// NeedBlocks`]) rather than reaching for a transport. Obtaining those
    /// blocks is the session's half ([`PeerSyncSession::materialize`]), which
    /// then calls this again **from the top**.
    ///
    /// Re-entry, not resumption. Nothing computed before the request survives
    /// it: the root lease, the reserved-namespace checks, the hazard reason,
    /// the record kind, the index row, symlink containment and every mutation
    /// fence are all read again from current state, because every one of them
    /// can move while the blocks are in flight. `satisfied` carries the one
    /// thing that cannot be recovered by re-reading -- what this path looked
    /// like on disk *before* the request went out -- so a local write that
    /// landed during the fetch is still caught. It is a staleness signal, not
    /// a licence to skip anything.
    // Each argument is an independent input to one attempt; the claim is the
    // obligation engine's, carried to the lane that may close it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn materialize_local(
        &self,
        group_id: &str,
        payload: &MaterializationPayload,
        policy: MaterializationPolicy,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        satisfied: Option<&BlockRequirement>,
        claim: Option<super::obligation_claims::PathClaim<'_>>,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        let outcome = self
            .materialize_local_inner(
                group_id,
                payload,
                policy,
                origin_device_id,
                authoring,
                satisfied,
                claim,
            )
            .await;
        // A newer version (or a deletion) is now this path's current record:
        // a custody lease this device holds for the version it replaced no
        // longer backs anything. The reconciler judges that; this only wakes
        // it, and not for a call that changed nothing (blocks still needed, or
        // an error).
        if matches!(outcome, Ok(LocalMaterializeOutcome::Concluded(_))) {
            self.state.nudge_custody_hold_reconciler();
        }
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    async fn materialize_local_inner(
        &self,
        group_id: &str,
        payload: &MaterializationPayload,
        policy: MaterializationPolicy,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        satisfied: Option<&BlockRequirement>,
        claim: Option<super::obligation_claims::PathClaim<'_>>,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        let root_commit_authority = self.root_lease_for(group_id)?;
        let root_commit_authority_op = root_commit_authority.begin_operation()?;
        let root_commit_permit = root_commit_authority_op.permit();
        let mut plan = self
            .admit_materialization(
                group_id,
                payload,
                origin_device_id,
                authoring,
                satisfied,
                &root_commit_permit,
            )
            .await?;
        plan.claim = claim;
        let record = plan.record;

        // a tombstone (`deleted=true, blocks=[]`) materialized via
        // the ordinary path below unconditionally fetches/reconstructs —
        // writing a 0-byte file at the path while the index records
        // `deleted=true`, an on-disk ghost file disagreeing with its own
        // index row. Handle deletion explicitly instead: remove the file
        // first (already gone is not an error — that's the common case,
        // since most tombstones arrive after the originating device's own
        // delete already ran locally), and only then record the
        // tombstone. Order matters: recording the tombstone
        // *before* a removal that then fails (a locked/open file, common
        // on Windows) leaves the index saying `deleted=true` while the
        // file still exists — the next scan sees an on-disk file with no
        // matching not-deleted index entry and resurrects + re-propagates
        // it as a brand-new local edit. Removing first means a failure
        // here surfaces as a real error without corrupting the index.
        if record.deleted {
            // A tombstone has no content to fetch, so applying one is decided
            // entirely by this device's own state -- see
            // `LocalConvergenceExecutor::materialize_tombstone`, which is
            // where it lives and which a device with no peer at all runs
            // directly.
            return self
                .materialize_tombstone(group_id, record, origin_device_id, plan.permit)
                .await
                .map(LocalMaterializeOutcome::Concluded);
        }

        // A payload that IS a symlink never goes through the ordinary
        // block-fetch/reconstruct path below — it carries no content
        // blocks at all.
        //
        // The payload's kind, not the row's. Asking the row which lane to
        // take is the same provenance break as asking it what to write:
        // a supersession between the payload and this read routes V1's
        // payload down V2's lane, and the proof published at the end
        // names V1 either way.
        if payload.version().meta.record_kind == RecordKind::Symlink {
            return self.materialize_symlink_lane(&plan);
        }
        // Nor does a directory: it has no content to fetch or to defer to a
        // placeholder, whatever the policy.
        if payload.version().meta.record_kind == RecordKind::Directory {
            return self.materialize_directory_lane(&plan);
        }

        // Content-identical fast path — if
        // this exact block list is already what's indexed locally for
        // this path, skip the whole fetch/reconstruct cycle below
        // entirely and just make sure the on-disk exec bit matches the
        // index (see `try_apply_metadata_only_update`'s doc comment for
        // the wire-schema caveat this still operates under). Skipped
        // entirely when hazardous: applying a chmod through this path
        // assumes the file already exists on disk under this exact name,
        // which is never true for a held file — falling through to the
        // eager/placeholder branch below routes it through `hold` instead.
        if let Some(outcome) = self.settle_metadata_only_update(&plan)? {
            return Ok(outcome);
        }

        // Policy-driven eager fetch is gated on this session's per-group
        // budget — see `MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION`'s doc comment;
        // once exhausted, this falls through to the placeholder branch below
        // instead of continuing to fetch.
        // Admission is charged, not merely consulted: `admit_eager_blocks`
        // adds this record's blocks to the group's session budget. So it must
        // be asked exactly once per record, and a pass re-entered after a
        // block request already carries its answer -- the request could only
        // have been handed out by a pass that was admitted. Charging again
        // would halve this session's real capacity, and for a record larger
        // than half the ceiling it would fail the second time, dropping
        // content this device has just successfully fetched to a placeholder
        // for the rest of the session.
        let eager_admitted = policy == MaterializationPolicy::Eager
            && (satisfied.is_some()
                || self.admit_eager_blocks(group_id, record.blocks.len() as u64));

        if eager_admitted {
            self.materialize_eager_lane(&plan).await
        } else {
            self.materialize_on_demand_lane(&plan)
        }
    }

    /// The admission stage of [`Self::materialize_local`]: every check that
    /// must pass before any lane may touch disk, and the one hazard answer
    /// every lane then shares.
    async fn admit_materialization<'a>(
        &self,
        group_id: &'a str,
        payload: &'a MaterializationPayload,
        origin_device_id: &'a str,
        authoring: Option<&'a yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        satisfied: Option<&'a BlockRequirement>,
        root_commit_permit: &'a RootCommitPermit<'a>,
    ) -> Result<MaterializationPlan<'a>, PeerSessionError> {
        // Bound once from the payload, never from the row. The version
        // that names these bytes travels with them in `payload`.
        let record = payload.record();
        yadorilink_peer_session::dst_trace(&record.path, || {
            format!(
                "materialize on {}: deleted={} blocks={} origin={origin_device_id}",
                self.local_device_id,
                record.deleted,
                record.blocks.len()
            )
        });
        // Peer input is never authority to adopt a folder. The watcher/link
        // path may adopt during explicit startup, but every peer-driven disk
        // mutation must prove that the already-adopted marker/token pair still
        // matches before it removes, creates, truncates, or renames anything.
        let sync_root = self.sync_root(group_id)?;
        self.state.verify_root(&sync_root, group_id)?;
        // Defense-in-depth: `dag_store::admit_change` already rejects any
        // change naming a versioned reserved-namespace artefact before it
        // is admitted (`apply_locked_record`'s only proof of `record`'s
        // provenance is that its authoring change is present, which says
        // nothing about when that change was admitted — a change written
        // before this check existed, or one that reached the index through
        // some other future path, must not get a second chance to reach
        // disk here). No caller of this function may materialize an
        // artefact component no matter how `record.path` got here.
        //
        // Deliberately `path_has_artefact_component_in_wire_path`, NOT the
        // host-`Path` form `path_has_artefact_component`: `record.path` is
        // peer-authored, not walked off this device's own disk, so
        // resolving it through this process's own `std::path::Path` would
        // make this check depend on which OS is running it — see that
        // function's doc comment. Also NOT the broader exclusion
        // predicate: a legacy `.yadorilink-tmp.`-marked path can be a
        // genuine user file (the marker is a substring match, and
        // recovery never deletes a file by its name,
        // so such a look-alike is safe) or an already-admitted change
        // from before this module existed — either way it must still
        // materialize, matching admission's own choice of predicate. See
        // `reserved_namespace`'s "Two predicates, not one".
        //
        // ALSO rejects `sync_root_lock::wire_path_names_sync_root_lock`, for
        // the identical wire-vs-host reason and the identical defense-in-
        // depth rationale as the artefact check above — `dag_store::
        // admit_change`'s `validate_no_reserved_paths` already rejects this
        // at admission, but a change admitted before that check existed (or
        // through a future path that skips it) must not get a second chance
        // to reach disk here. Without this, a peer materializing
        // `.yadorilink-root.lock` replaces the on-disk lock file out from
        // under this device's own live OS lock (held on the now-unlinked
        // inode on Unix), and a second daemon then locks the fresh file
        // materialization just created at the same path — two processes each
        // believing they exclusively own this sync root, exactly the state
        // `sync_root_lock` exists to make unreachable.
        if yadorilink_fs_platform::reserved_namespace::path_has_artefact_component_in_wire_path(
            &record.path,
        ) || yadorilink_root_authority::sync_root_lock::wire_path_names_sync_root_lock(
            &record.path,
        ) {
            return Err(PeerSessionError::ReservedNamespaceCollision(record.path.clone()));
        }
        // Same defense-in-depth reasoning as the reserved-artefact/lock
        // check above, for a different hazard: `record.path` may name a
        // path that cannot be faithfully stored on a Windows device at all
        // (a trailing '.'/' ' component — see
        // `path_has_non_portable_wire_component`'s doc comment).
        // `dag_store::admit_change` already refuses this at admission, but
        // a record whose authoring change was admitted before this check
        // existed (or reached the index through some other future path)
        // must not get a second chance to reach disk here — writing it
        // would let this path silently alias a different on-disk name than
        // the one this device's own index believes it just materialized.
        if yadorilink_fs_platform::reserved_namespace::path_has_non_portable_wire_component(
            &record.path,
        ) {
            return Err(PeerSessionError::NonPortablePath(record.path.clone()));
        }
        // Computed once, ahead of every
        // dispatch branch below (symlink, metadata-only fast path, eager
        // fetch, placeholder, AND the tombstone branch immediately below) —
        // a hazard must short-circuit before *any* of those reach their own
        // atomic temp-write step or physical delete, not just the
        // ordinary-file ones. See `hazard_reason_for`'s doc comment.
        // `hazard_reason_for_policy` compares `record.path` against
        // siblings regardless of `record.deleted`, so this is meaningful
        // for a tombstone too: a case-fold/Unicode-normalization collision
        // makes it genuinely ambiguous which physical file a delete for
        // this logical path would remove, and a delete is less reversible
        // than a wrong write (no peer re-send recovers deleted bytes), so
        // it needs the same guard, not an exemption.
        let hazard_reason = self.hazard_reason_for(group_id, record).await?;
        Ok(MaterializationPlan {
            group_id,
            payload,
            record,
            origin_device_id,
            authoring,
            columns:
                yadorilink_replica_domain::session_state::LocalFileMetaColumns::from_version_meta(
                    &payload.version().meta,
                ),
            satisfied,
            hazard_reason,
            permit: root_commit_permit,
            claim: None,
        })
    }

    /// Content-identical fast path: when the payload's block list is already
    /// what this path has indexed, only its metadata is applied and the
    /// result verified. `None` falls through to the fetching lanes.
    fn settle_metadata_only_update(
        &self,
        plan: &MaterializationPlan<'_>,
    ) -> Result<Option<LocalMaterializeOutcome>, PeerSessionError> {
        let MaterializationPlan {
            group_id,
            payload,
            record,
            origin_device_id,
            authoring,
            permit: root_commit_permit,
            ..
        } = *plan;
        if plan.hazard_reason.is_none() {
            let root = self.sync_root(group_id)?;
            let update = match try_apply_metadata_only_update(
                self.state.as_ref(),
                &root,
                group_id,
                record,
                origin_device_id,
                authoring,
                payload.version(),
                root_commit_permit,
            ) {
                // The file already here cannot be read by its owner, so this
                // version's metadata can be neither confirmed nor applied, and
                // nothing was mutated. Held rather than retried or replaced:
                // retrying fails the same way until the file itself changes.
                Err(PeerSessionError::MetadataUnprovable(_)) => {
                    let reason = self.state.hold_metadata_unprovable(
                        group_id,
                        &record.path,
                        &root.join(&record.path),
                        &payload.version().version_hash,
                    )?;
                    return Ok(Some(
                        MaterializeResult::Settled(SettlementEvidence::HazardHeld { reason })
                            .into(),
                    ));
                }
                other => other?,
            };
            if let Some(update) = update {
                self.state.clear_held(group_id, &record.path)?;
                // `try_apply_metadata_only_update` itself already decided
                // snapshot vs. bump based on whether applying metadata
                // actually changed anything on disk -- see its own doc
                // comment.
                // The payload's kind, matching the version the proof
                // names -- `exact_object_evidence_after_write` verifies
                // disk against this kind, so reading it from the row
                // would let the verification ask about a different
                // object than the one just written.
                let kind = payload.version().meta.record_kind;
                return match self.exact_object_evidence_after_write(
                    group_id,
                    &record.path,
                    kind,
                    payload.version(),
                    update.mutation_generation,
                    &update.xattrs,
                )? {
                    Some(evidence) => Ok(Some(MaterializeResult::Settled(evidence).into())),
                    None => Ok(Some(MaterializeResult::RetryRequired.into())),
                };
            }
        }
        Ok(None)
    }

    /// Holds a hazardous record instead of writing anything under its name,
    /// and settles with that as the evidence.
    fn hold_for_hazard(
        &self,
        plan: &MaterializationPlan<'_>,
        reason: &str,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        self.hold(
            plan.group_id,
            plan.record,
            reason,
            plan.origin_device_id,
            plan.authoring,
            &plan.columns,
        )?;
        Ok(MaterializeResult::Settled(SettlementEvidence::HazardHeld { reason: reason.to_owned() })
            .into())
    }
}
