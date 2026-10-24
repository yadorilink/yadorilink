use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use yadorilink_local_storage::check_disk_headroom;
use yadorilink_local_storage::{
    verify_write_target_within_canonical_root, verify_write_target_within_root,
};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::session_state::LinkGate;
use yadorilink_replica_domain::session_state::MaterializationPolicy;

use super::types::*;
use super::{mode_and_xattrs_match_disk, Election, OwnCaptureOnDisk, OwnCaptureRule, Recapture};
use yadorilink_fs_platform::fs_identity::disk_race_fingerprint_or_stat;
use yadorilink_peer_session::peer_session::*;
use yadorilink_replica_domain::native_plan::{NativePlannedNode, NativeRowIdentity};

impl super::LocalConvergenceExecutor {
    /// [`Self::block_requirement_for`] once the version is in hand.
    fn block_requirement_for_version(
        &self,
        group_id: &str,
        path: &str,
        version: &FileVersion,
    ) -> Result<Option<BlockRequirement>, PeerSessionError> {
        let record = file_record_from_version(path, version);
        if record.deleted || !self.blocks_missing_locally(group_id, &record)? {
            return Ok(None);
        }
        // Sampled now, before anything is requested, so the guard against
        // a local editor writing during the fetch has something from
        // before the window to compare against.
        let observed_disk = self
            .local_file_path(group_id, path)
            .ok()
            .and_then(|out_path| disk_race_fingerprint_or_stat(&out_path));
        Ok(Some(BlockRequirement {
            path: path.to_string(),
            version_hash: version.version_hash,
            record,
            observed_disk,
        }))
    }

    /// The content this device is missing locally, from native's
    /// materialization plan: what prefetch acts on.
    ///
    /// Each requirement is keyed by its PHYSICAL path (a copy's own name,
    /// which is where the pass will look for it) and demanded by its
    /// SOURCE path (the head's logical path). A version native cannot resolve is not "nothing to fetch": the
    /// plan cannot be made and the error is the answer.
    pub fn content_missing_locally_from_native(
        &self,
        group_id: &str,
        paths: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<BlockRequirement>, PeerSessionError> {
        Ok(self
            .planned_missing_content(group_id, paths)?
            .into_iter()
            .map(|planned| planned.requirement)
            .collect())
    }

    /// [`Self::content_missing_locally_from_native`], each requirement
    /// paired with the source path whose head demanded it -- what the
    /// prefetch needs to notice that a plan went stale before it asks a
    /// peer for anything.
    pub(crate) fn planned_missing_content(
        &self,
        group_id: &str,
        paths: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<PlannedRequirement>, PeerSessionError> {
        use yadorilink_replica_domain::native_plan::NativePlannedNode;
        let mut parents: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
            std::collections::BTreeMap::new();
        for path in paths {
            parents
                .entry(super::namespace_steps::parent_of(path).to_owned())
                .or_default()
                .insert(path.clone());
        }
        let mut missing = Vec::new();
        for (parent, on_level) in parents {
            let plan = self
                .state
                .native_plan_for_names(group_id, &parent, &on_level)
                .map_err(crate::sync_error::SyncError::from)
                .map_err(PeerSessionError::from)?;
            for (physical, node) in &plan.nodes {
                let NativePlannedNode::Entry { head, .. } = node else { continue };
                if !paths.contains(head.source_path.as_str()) && !paths.contains(physical.as_str())
                {
                    continue;
                }
                let version = self
                    .state
                    .dag_get_file_version(group_id, &head.version())?
                    .ok_or_else(|| {
                        PeerSessionError::from(crate::sync_error::SyncError::from(
                            yadorilink_sync_sqlite::SyncSqliteError::NotFound(format!(
                                "native plan names version {} at {} that is not stored",
                                head.version().to_hex(),
                                physical.as_str()
                            )),
                        ))
                    })?;
                if let Some(requirement) =
                    self.block_requirement_for_version(group_id, physical.as_str(), &version)?
                {
                    missing.push(PlannedRequirement {
                        source_path: head.source_path.clone(),
                        requirement,
                    });
                }
            }
        }
        Ok(missing)
    }

    /// Reconcile `paths` using only what this device already holds.
    ///
    /// The whole of convergence except obtaining content: everything here is
    /// decided from this device's own disk, index and native state. A path whose
    /// content is absent records a retriable placeholder and stays open.
    pub async fn reconcile_paths(
        &self,
        group_id: &str,
        paths: std::collections::BTreeSet<String>,
    ) -> Result<Option<ProjectionAttempt>, PeerSessionError> {
        let audit_attempt_id = next_audit_attempt_id();
        // This entry point obtains no content (it reconciles from what this
        // device already holds), so its timer has no block-fetch half to
        // share -- created here purely to satisfy the one-timer-per-attempt
        // shape the fetching entry point needs.
        let call_timer = crate::local_convergence::call_timer::ReconcileCallTimer::new();
        self.reconcile_group_paths_guarded(
            group_id,
            paths,
            &self.local_device_id,
            &HashMap::new(),
            None,
            audit_attempt_id,
            &call_timer,
        )
        .await
    }

    /// Whether the hazard re-check would only repeat its last decision for
    /// `path`: the path is held because its existing file is not readable
    /// by its owner, and neither that file, the path's mutation fence nor
    /// the version the path resolves to has changed since. Re-running the
    /// path then cannot come out differently, so the sweep skips it rather
    /// than re-examining it on every tick. Any other hold, and a path that
    /// no longer resolves to content, is re-examined as before.
    pub(crate) fn metadata_unprovable_hold_unchanged(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        let held_for_metadata = self.state.get_held_state(group_id, path)?.is_some_and(|held| {
            held.reason
                .starts_with(yadorilink_peer_session::hazard::HELD_REASON_METADATA_UNPROVABLE)
        });
        if !held_for_metadata {
            return Ok(false);
        }
        let Some(NativePlannedNode::Entry { head, .. }) =
            self.native_planned_node(group_id, path)?
        else {
            return Ok(false);
        };
        let version = head.version();
        let out_path = self.sync_root(group_id)?.join(path);
        self.state.metadata_unprovable_hold_unchanged(group_id, path, &out_path, &version)
    }

    fn block_write_activity_provider(
        &self,
    ) -> Arc<dyn yadorilink_peer_session::peer_session::BlockWriteActivityProvider> {
        self.block_write_activity_provider.clone()
    }

    /// `reconcile_one_file`'s guard: if a handle is set and it reports a
    /// pending, undispatched local entry for `rel_path`, that entry is now
    /// captured into the index by the time this returns. Called *before*
    /// `reconcile_one_file` acquires `SyncState::path_lock` for the same
    /// path — the handle's own flush goes through the ordinary
    /// `LocalChangeProcessor::process_event_with_ignore` dispatch, which
    /// acquires that same lock itself, so calling this while already
    /// holding it (as `reconcile_one_file` does for the rest of its body,
    /// including every `materialize`/`resolve_and_apply_conflict` call
    /// downstream of it) would deadlock. Because every `materialize` call
    /// in this module happens from within `reconcile_one_file`'s
    /// already-locked body, this single guard — run once, up front —
    /// covers both the "materialize-side" and
    /// "`reconcile_one_file`-side" serialization requirements: by the time
    /// any downstream `materialize` call writes to disk, a local change
    /// that was still pending here has already been indexed.
    pub(crate) async fn flush_pending_local_change_before_reconcile(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        let handle = self.pending_local_change_flush.clone();
        // Marks that the guard was reached for this path — the first fork
        // when a local write is lost despite this guard existing. A missing
        // trace line here means the guard never ran on that route at all,
        // which is a different bug from it running and finding nothing.
        yadorilink_peer_session::dst_trace(rel_path, || {
            format!("flush guard entered on {}", self.local_device_id)
        });
        tracing::debug!(
            group_id,
            path = rel_path,
            "checking this link's debounce accumulator for a pending local change before reconciling this path"
        );
        handle.flush_pending_local_change(group_id, rel_path).await
    }

    /// Both pre-write guards for `rel_path` -- its own pending edit and a
    /// case-fold sibling's -- settled only if both are. `RetryRequired`
    /// means a local edit may be sitting uncaptured on disk, and the caller
    /// must not write to (or delete) the path on this pass.
    pub(crate) async fn flush_local_changes_before_reconcile(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        let ancestors = self.capture_vanished_explicit_ancestors(group_id, rel_path).await;
        let own = self.flush_pending_local_change_before_reconcile(group_id, rel_path).await;
        let sibling = self.flush_case_fold_sibling_before_reconcile(group_id, rel_path).await;
        ancestors.and(own).and(sibling)
    }

    /// Captures the removal of each ancestor of `rel_path` that the index
    /// holds as a live explicit directory but that is gone from disk,
    /// before anything is written below it.
    ///
    /// Writing `rel_path` creates its missing ancestors. An explicit
    /// directory the user just removed (`rm -rf`) whose removal capture has
    /// not seen yet would come back that way -- and capture, finding it on
    /// disk again, would never author its deletion: the user's delete of
    /// the directory would be lost, and the directory kept as an explicit
    /// entry for good instead of as the container of what arrived in it.
    /// Capturing first turns it into the point deletes the removal was, so
    /// the write recreates the ancestor only as the structural container it
    /// now is. An ancestor the materializer is still placing (an open
    /// intent) is not a removal.
    async fn capture_vanished_explicit_ancestors(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        let Ok(root) = self.sync_root(group_id) else {
            return PendingLocalFlushOutcome::Settled;
        };
        let mut outcome = PendingLocalFlushOutcome::Settled;
        let components: Vec<&str> = rel_path.split('/').collect();
        for depth in 1..components.len() {
            let ancestor = components[..depth].join("/");
            let vanished = matches!(
                std::fs::symlink_metadata(root.join(&ancestor)),
                Err(error) if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                )
            );
            if !vanished {
                continue;
            }
            // A row that cannot be read is not "not explicit": writing below the
            // vanished ancestor would recreate a directory the user may have
            // removed, so the pass is retried instead.
            let row =
                match self.state.file_index_repository().canonical_current_row(group_id, &ancestor)
                {
                    Ok(row) => row,
                    Err(error) => {
                        tracing::warn!(
                            group_id,
                            ancestor,
                            %error,
                            "cannot read an ancestor that vanished from disk; retrying the path"
                        );
                        return PendingLocalFlushOutcome::RetryRequired;
                    }
                };
            let explicit = row.is_some_and(|row| {
                !row.snapshot.deleted
                    && row.snapshot.record_kind
                        == yadorilink_replica_domain::file::RecordKind::Directory
            });
            let in_flight = match self
                .state
                .materialization_intent_repository()
                .has_materialization_intent(group_id, &ancestor)
            {
                Ok(in_flight) => in_flight,
                Err(error) => {
                    tracing::warn!(
                        group_id,
                        ancestor,
                        %error,
                        "cannot read the intent of an ancestor that vanished from disk; \
                         retrying the path"
                    );
                    return PendingLocalFlushOutcome::RetryRequired;
                }
            };
            if explicit && !in_flight {
                outcome = outcome.and(
                    self.pending_local_change_flush
                        .capture_local_path_state(group_id, &ancestor)
                        .await,
                );
                // Everything below it was removed with it and has just
                // been captured; there is nothing deeper to look for.
                break;
            }
        }
        outcome
    }

    /// Like `flush_pending_local_change_before_reconcile` above, but for
    /// the *other* case-variant path that would collide with `rel_path` on
    /// a case-insensitive filesystem.
    ///
    /// Without this, `hazard_reason_for`'s `state.list_files(group_id)`
    /// read (used to detect a case-fold collision before materializing an
    /// incoming record — see `hazard_reason_for_policy`) only sees what's
    /// already indexed in `SyncState`. A local write to the colliding
    /// sibling name, still sitting undispatched in this link's debounce
    /// accumulator, is invisible to that read — so the incoming record
    /// for the other case-variant can materialize for real (no collision
    /// detected) instead of being held, silently overwriting/losing this
    /// device's own not-yet-indexed write with no conflict artifact at
    /// all. Same failure shape `flush_pending_local_change_before_
    /// reconcile` already closes for the exact-same-path case, just
    /// reached via case-fold adjacency instead of path identity.
    ///
    /// Only meaningful (and only called) when `hazard::is_case_insensitive_
    /// filesystem` is true for this group's root — on a case-sensitive
    /// filesystem, two differently-cased names are simply unrelated
    /// files, and this extra round trip would have nothing to find.
    pub(crate) async fn flush_case_fold_sibling_before_reconcile(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        // No root for this group means nothing of ours is on disk to collide
        // with, so there is no case-fold sibling to flush.
        let Ok(root) = self.sync_root(group_id) else {
            return PendingLocalFlushOutcome::Settled;
        };
        let case_insensitive =
            self.volume_probes.folding(&root).await.case_insensitive.unwrap_or(true);
        if !case_insensitive {
            return PendingLocalFlushOutcome::Settled;
        }
        let handle = self.pending_local_change_flush.clone();
        tracing::debug!(
            group_id,
            path = rel_path,
            "checking this link's debounce accumulator for a pending case-fold sibling change before reconciling this path"
        );
        handle.flush_case_fold_sibling(group_id, rel_path).await
    }

    /// attempts to admit `block_count` more blocks to eager
    /// fetch for `group_id` under this session's cumulative budget
    /// (`MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION`), returning whether the
    /// admission succeeded. On success, the group's counter is
    /// incremented by `block_count`; on failure, the counter is
    /// unchanged and the caller is expected to fall back to a
    /// placeholder instead of fetching.
    /// How many blocks this session has charged to `group_id`'s eager
    /// admission budget so far. Exists so a test can assert that a record is
    /// charged for exactly once, which a materialization that hands out a
    /// block request and is then re-entered could easily get wrong: the
    /// charge is a side effect, not a recomputable value.
    #[cfg(any(test, feature = "test-support"))]
    pub fn eager_blocks_admitted(&self, group_id: &str) -> u64 {
        let admission = self.eager_admission.lock().unwrap_or_else(|p| p.into_inner());
        admission.get(group_id).copied().unwrap_or(0)
    }

    pub(crate) fn admit_eager_blocks(&self, group_id: &str, block_count: u64) -> bool {
        let mut admission =
            self.eager_admission.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        admit_eager_blocks_impl(
            &mut admission,
            group_id,
            block_count,
            MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION,
        )
    }

    /// Thin wrapper over `hold_record`
    /// (see that free function's doc comment) using this session's own
    /// `SyncState`.
    pub(crate) fn hold(
        &self,
        group_id: &str,
        record: &FileRecord,
        reason: &str,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
    ) -> Result<(), PeerSessionError> {
        let authority = self.root_lease_for(group_id)?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        hold_record(
            self.state.as_ref(),
            group_id,
            record,
            reason,
            origin_device_id,
            authoring,
            meta,
            &permit,
        )
    }

    /// Builds `SettlementEvidence::ExactObject` from the row `materialize`
    /// just durably committed for `path` -- the version identity is read
    /// back from the just-written row rather than threaded in as a
    /// parameter, since none of `materialize`'s own branches ever receive
    /// a `VersionHash` directly (`FileRecord` carries no such field).
    /// `mutation_generation` is the fence value the caller's own bump (or,
    /// for a content-identical verification, snapshot) returned.
    /// `written` is the version the physical write put on disk, carried
    /// from the payload that produced those bytes.
    ///
    /// This function does not decide the version and has no way to. It
    /// confirms that the target version is still what the row names, and
    /// that the object on disk matches it in kind and in replicated
    /// xattrs. There is deliberately no API left that discovers a proof's
    /// version from the row: that is how a write for V1 came to be
    /// published as V2, and leaving such a helper in place -- even unused
    /// -- is how it would come back.
    ///
    /// `None` means the row has moved off `written` since: the bytes are
    /// real but they are no longer what this path wants, so there is no
    /// exact claim to make and the caller must retry rather than settle.
    pub(crate) fn exact_object_evidence_after_write(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        written: &FileVersion,
        mutation_generation: i64,
        xattrs: &XattrEvidence,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        let current_version = self
            .state
            .get_current_version_record(group_id, path)?
            .map(|current| current.to_file_version())
            .ok_or_else(|| {
                PeerSessionError::CorruptState(format!(
                    "materialize committed {path} but its version record is unexpectedly absent"
                ))
            })?;
        if current_version.version_hash != written.version_hash {
            return Ok(None);
        }
        let version = written.version_hash;
        let out_path = self.local_file_path(group_id, path)?;
        // The `ExactObject` proof gate: `version_hash` bakes replicated
        // xattr bytes directly into its identity (`FileVersion::compute_
        // hash`), so this evidence must never claim exactness without a
        // strict, on-disk confirmation that they actually landed --
        // `apply_xattrs` itself never surfaces a `fsetxattr`/`fremovexattr`
        // failure as an `Err`, so nothing upstream of this call would
        // otherwise ever catch one. Scoped to `RecordKind::File` only,
        // matching `verify_replicated_xattrs_exact`'s own contract: a
        // symlink/directory version's `xattrs` is always empty (never
        // scanned, see `FileMeta::xattrs`'s own doc) and its path must
        // never be opened with symlink-following semantics here (a
        // dangling symlink is perfectly valid and has no followable
        // target at all).
        //
        // A caller that just wrote the file passes the attempt's own
        // confirmation, taken before the final mode was applied; one that
        // did not passes `ReproveFromDisk`, and disk is re-read strictly.
        if kind == RecordKind::File {
            require_xattr_evidence(path, &out_path, &written.meta.xattrs, xattrs)?;
        }
        // Defense-in-depth: `FileVersion`
        // accepts `RecordKind::Directory` (and, in principle, a
        // `RecordKind::Symlink` whose disk object is something else
        // entirely), but `materialize()` has no directory-specific
        // physical branch today -- a directory version falls through to
        // the ordinary regular-file reconstruct path, which creates a
        // regular file, not a directory. Without this check, a
        // hand-crafted, validly-signed version claiming `Directory` could
        // settle as `ExactObject` while the physical object on disk is a
        // `RegularFile`. `FileIdentity::observe_path(...).ok()` below
        // this point silently accepts `None` too (no disk object at all),
        // so this also closes that gap for every kind, not just
        // Directory.
        require_physical_kind_matches(path, &out_path, kind)?;
        Ok(Some(SettlementEvidence::ExactObject {
            kind,
            version,
            identity: Box::new(
                yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path).ok(),
            ),
            mutation_generation,
        }))
    }

    /// Does this device hold every block `record` names, *as this group*?
    ///
    /// Both halves matter. A block present in the store but with no provenance
    /// for this group was obtained by some other group and is not this one's
    /// to use, which is exactly the condition the block lane treats as
    /// missing. Purely local: two batched reads, no network.
    pub(crate) fn blocks_missing_locally(
        &self,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<bool, PeerSessionError> {
        self.blocks_missing_locally_in_batch(group_id, record, None)
    }

    /// As [`Self::blocks_missing_locally`], but a block an earlier file in the
    /// same reconciliation window already obtained counts as held even though
    /// its provenance row is still queued behind that window's batch flush.
    fn blocks_missing_locally_in_batch(
        &self,
        group_id: &str,
        record: &FileRecord,
        batch: Option<&ReconcileProvenanceBatch>,
    ) -> Result<bool, PeerSessionError> {
        if record.blocks.is_empty() {
            return Ok(false);
        }
        let hashes: Vec<_> = record.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
        let present = self.store.present_blocks(&hashes)?;
        let provenance = self.state.group_has_block_provenance_batch(
            group_id,
            &record.blocks.iter().map(|b| b.hash.clone()).collect::<Vec<_>>(),
        )?;
        Ok(record.blocks.iter().zip(present).any(|(block, present)| {
            !present
                || !(provenance.contains(&block.hash)
                    || batch.is_some_and(|b| b.already_known(&block.hash)))
        }))
    }

    /// defense-in-depth check before writing through `out_path`
    /// — see `chunker::verify_write_target_within_canonical_root`'s doc
    /// comment. Uses the cached canonical root (`canonical_sync_roots`)
    /// when available (the common case, avoiding a repeated
    /// canonicalize-the-whole-root cost on this per-peer-message hot
    /// path); falls back to resolving `group_id`'s root fresh for the
    /// rare case it wasn't cached at session construction time.
    ///
    /// Also re-runs `VerifiedRoot::verify` — `materialize`'s own
    /// verification at its own start proves the root's identity BEFORE
    /// any block fetch, but a fetch can run for up to
    /// `DEFAULT_HYDRATION_TIMEOUT` (30s), during which the mountpoint
    /// this device resolved as the sync root can be unmounted and
    /// replaced (a fresh empty directory, or a different volume) without
    /// changing anything a bare `canonicalize`/containment check can see
    /// — a replaced mountpoint's path still resolves and still contains
    /// `out_path` lexically. Since this function already runs immediately
    /// before every physical write in every `materialize`/`hydration::hydrate_inner`
    /// with_timeout` branch, re-verifying identity here (not just
    /// containment) closes that window at its narrowest point, for both
    /// callers, in one place — cheap enough to run unconditionally: one
    /// canonicalize, one lock, and one marker-file read, not a directory
    /// walk.
    /// The structural-directory ledger every `mkdir` this executor runs
    /// in `group_id`'s root records into.
    pub(crate) fn structural_ledger<'a>(
        &'a self,
        group_id: &'a str,
    ) -> yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger<'a> {
        yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger::new(
            self.state.as_ref(),
            group_id,
        )
    }

    pub fn verify_write_target(
        &self,
        group_id: &str,
        out_path: &Path,
    ) -> Result<(), PeerSessionError> {
        // Resolve the root first and fail closed on an unknown group: with the
        // old empty-path default, `out_path` was a bare relative filename whose
        // parent is `""` -- exactly the empty root -- so the fast path below
        // returned Ok and this check passed trivially for the one case it most
        // needed to reject.
        let raw_root = self.sync_root(group_id)?;
        let raw_root = raw_root.as_path();
        self.state.verify_root(raw_root, group_id)?;
        // Fast path: is specifically about a symlink at an
        // *intermediate* directory component between the sync root and
        // the file — when `out_path`'s parent *is* the sync root itself
        // (an ordinary top-level file, no subdirectory in `record.path`
        // at all), there is no intermediate component that could be such
        // a symlink, so the expensive canonicalize round trip has nothing
        // to catch here. Purely structural (no filesystem access) — safe
        // to check before paying for the syscalls below, and matters in
        // practice: this runs on every eager materialize/hydrate, a
        // per-peer-message-concurrency-bounded hot path where two peers
        // can legitimately race each other fetching each other's content
        // for the two sides of the same conflict.
        if out_path.parent() == Some(raw_root) {
            return Ok(());
        }
        match self.canonical_sync_root(group_id, raw_root) {
            Some(canonical_root) => Ok(verify_write_target_within_canonical_root(
                out_path,
                &canonical_root,
                &self.structural_ledger(group_id),
            )?),
            None => Ok(verify_write_target_within_root(
                out_path,
                raw_root,
                &self.structural_ledger(group_id),
            )?),
        }
    }

    /// Disk-space headroom preflight
    /// before a hydration fetch or a materialize-to-temp-and-rename write
    /// begins, scoped to the volume hosting `group_id`'s local sync root —
    /// called from both of this session's write paths that reach
    /// `reconstruct_file` (`hydration::hydrate_inner`'s single-session
    /// hydration, and `materialize`'s eager-fetch branch). A no-op (fast
    /// path, no filesystem query) when `headroom_enforced` hasn't been
    /// turned on — see that field's doc comment for why a bare/test session
    /// doesn't enforce this by default.
    ///
    /// The bytes it admits stay reserved until the returned guard is dropped,
    /// and every later preflight sees the volume's free space less what is
    /// reserved: files that each fit but together do not are refused, not
    /// left to run out of space mid-write.
    pub(crate) fn preflight_disk_headroom(
        &self,
        group_id: &str,
        target_path: &Path,
        additional_bytes: u64,
    ) -> Result<HeadroomReservation, PeerSessionError> {
        if !self.headroom_enforced() {
            return Ok(HeadroomReservation { held: None });
        }
        let root = self.sync_root(group_id)?;
        let volume_key = volume_key(&root);
        #[cfg(any(test, feature = "test-support"))]
        let volume_key = self
            .volume_key_override
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .unwrap_or(volume_key);
        let volume = headroom_ledger_for(&volume_key);
        let override_bytes = self.headroom_override_bytes();
        reserve_on_volume(&volume, additional_bytes, |wanted| {
            #[cfg(any(test, feature = "test-support"))]
            {
                let probe = self.free_space_probe.lock().unwrap_or_else(|p| p.into_inner()).clone();
                if let Some(probe) = probe {
                    probe();
                }
                let fake = *self.fake_available_bytes.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(available_bytes) = fake {
                    let space = yadorilink_local_storage::VolumeFreeSpace {
                        available_bytes,
                        total_bytes: available_bytes,
                        headroom_bytes: override_bytes.unwrap_or(0),
                    };
                    return if space.would_breach(wanted) {
                        Err(yadorilink_local_storage::StorageError::DiskPressure {
                            path: target_path.to_path_buf(),
                            volume: root.clone(),
                            available_bytes: space.available_bytes,
                            headroom_bytes: space.headroom_bytes,
                        })
                    } else {
                        Ok(())
                    };
                }
            }
            check_disk_headroom(&root, target_path, wanted, override_bytes)
        })
        .map_err(Into::into)
    }
}

/// Reserves `additional_bytes` of the free space of the volume holding
/// `root`, for a write outside any executor (the daemon's own hydration and
/// restore): the same shared account, the same guard.
pub(crate) fn reserve_volume_headroom(
    root: &Path,
    target_path: &Path,
    additional_bytes: u64,
    override_bytes: Option<u64>,
) -> Result<HeadroomReservation, yadorilink_local_storage::StorageError> {
    let volume = headroom_ledger_for(&volume_key(root));
    reserve_on_volume(&volume, additional_bytes, |wanted| {
        check_disk_headroom(root, target_path, wanted, override_bytes)
    })
}

/// Check-and-reserve on one volume's account. Only this volume's admissions
/// are serialised, and the map lock is not held: a free-space query that
/// hangs (an unresponsive network mount) holds up this volume's preflights
/// and nobody else's, and never the release of a reservation, which is an
/// atomic. `check` gets the bytes the new write would add to those already
/// reserved.
fn reserve_on_volume<E>(
    volume: &Arc<VolumeLedger>,
    additional_bytes: u64,
    check: impl FnOnce(u64) -> Result<(), E>,
) -> Result<HeadroomReservation, E> {
    let _admitting = volume.admit.lock().unwrap_or_else(|p| p.into_inner());
    let wanted = additional_bytes.saturating_add(volume.reserved.load(Ordering::SeqCst));
    check(wanted)?;
    volume.reserved.fetch_add(additional_bytes, Ordering::SeqCst);
    Ok(HeadroomReservation { held: Some((volume.clone(), additional_bytes)) })
}

/// What identifies the volume holding `root`, so links on one volume share
/// one account of reserved space.
///
/// Known limitation: the key is the device id (Unix) or the drive component
/// (elsewhere), so two mappings of one network share can get separate
/// accounts and each admit writes against the same free space. Aliasing them
/// is out of scope; the failure is the pre-reservation behaviour, not worse.
fn volume_key(root: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(root) {
            return format!("dev:{}", meta.dev());
        }
    }
    let canonical = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    format!(
        "path:{}",
        canonical
            .components()
            .next()
            .map_or(String::new(), |c| { c.as_os_str().to_string_lossy().into_owned() })
    )
}

/// One volume's account of reserved space.
#[derive(Default)]
pub(crate) struct VolumeLedger {
    reserved: AtomicU64,
    /// Serialises a preflight's check-and-reserve on this volume.
    admit: std::sync::Mutex<()>,
}

/// The account of `volume`, shared by every link and peer session of the
/// process. The map lock is held only to fetch or create the entry; entries
/// stay (one small value per volume ever written to).
fn headroom_ledger_for(volume: &str) -> Arc<VolumeLedger> {
    static LEDGERS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Arc<VolumeLedger>>>> =
        std::sync::OnceLock::new();
    LEDGERS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .entry(volume.to_owned())
        .or_default()
        .clone()
}

/// Bytes reserved on the volume under `volume` right now.
#[cfg(test)]
pub(crate) fn reserved_on(volume: &str) -> u64 {
    headroom_ledger_for(volume).reserved.load(Ordering::SeqCst)
}

/// Bytes of free space an active write has claimed; released on drop. Shared
/// (`Arc`) by the awaiting write and its blocking assembly, so the space is
/// released only when the last of them is done with it.
pub(crate) struct HeadroomReservation {
    held: Option<(Arc<VolumeLedger>, u64)>,
}

impl HeadroomReservation {
    #[cfg(test)]
    pub(crate) fn for_tests(volume: &str, bytes: u64) -> Self {
        let ledger = headroom_ledger_for(volume);
        ledger.reserved.fetch_add(bytes, Ordering::SeqCst);
        Self { held: Some((ledger, bytes)) }
    }
}

impl std::fmt::Debug for HeadroomReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeadroomReservation")
            .field("bytes", &self.held.as_ref().map(|(_, bytes)| *bytes))
            .finish()
    }
}

impl Drop for HeadroomReservation {
    fn drop(&mut self) {
        if let Some((ledger, bytes)) = self.held.take() {
            ledger.reserved.fetch_sub(bytes, Ordering::SeqCst);
        }
    }
}

impl super::LocalConvergenceExecutor {
    /// Peer apply waits for the group's startup (initial scan and dirty-journal
    /// redrive) to have captured local state: an offline delete or edit is
    /// otherwise indistinguishable from an absent path and would be written
    /// over. Polled, not parked, so a slow startup never stalls other groups;
    /// not-yet-ready and failed alike defer and the caller retries. Local
    /// capture never asks, so it is never held.
    pub(crate) fn startup_admits_peer_apply(&self, group_id: &str) -> bool {
        matches!(
            futures_util::FutureExt::now_or_never(self.state.wait_group_ready(group_id)),
            Some(Ok(()))
        )
    }
}

impl super::LocalConvergenceExecutor {
    /// One bounded reconciliation attempt: acquires
    /// `MaterializationAuditGuard` for `group_id`, runs
    /// `reconcile_group_paths(paths)` under it, and releases the guard
    /// before returning — never holds it across more than one
    /// `reconcile_group_paths` call. Returns `Ok(None)` if the guard could
    /// not be acquired (another attempt for this group is already in
    /// flight) or the group is not `LinkGate::Live` — the caller decides
    /// what "could not run this attempt right now" means for its own
    /// retry/backoff.
    // Each argument is an independent input to one attempt; the claim is the
    // obligation engine's, carried to the lane that may close it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn reconcile_group_paths_guarded(
        &self,
        group_id: &str,
        paths: std::collections::BTreeSet<String>,
        origin_device_id: &str,
        prefetched: &HashMap<String, BlockRequirement>,
        claims: Option<&super::obligation_claims::ObligationClaims>,
        audit_attempt_id: u64,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<Option<ProjectionAttempt>, PeerSessionError> {
        if !matches!(
            self.state.directory_link_gate_for_group(group_id)?,
            Some(LinkGate::Live { .. })
        ) {
            return Ok(None);
        }
        if !self.startup_admits_peer_apply(group_id) {
            return Ok(None);
        }
        let Some(_guard) = MaterializationAuditGuard::try_acquire(&self.state, group_id) else {
            return Ok(None);
        };
        let _ = audit_attempt_id;
        Ok(Some(
            self.reconcile_group_paths_native(
                group_id,
                paths,
                origin_device_id,
                prefetched,
                claims,
                call_timer,
            )
            .await?,
        ))
    }

    /// Captures what `target_path` holds now, for an own captured head the
    /// disk has moved on from, and says whether that superseded `head`.
    /// Called without the path lock, which capture takes itself.
    /// Projects the node native's plan puts at `target_path`: the native
    /// counterpart of [`Self::materialize_dag_content_head`]. `planned` is
    /// compared with a fresh plan under the path lock, and anything other
    /// than the same node declines.
    pub(crate) async fn materialize_native_entry(
        &self,
        group_id: &str,
        target_path: &str,
        planned: &NativePlannedNode,
        policy: MaterializationPolicy,
        satisfied: Option<&BlockRequirement>,
        claim: Option<super::obligation_claims::PathClaim<'_>>,
    ) -> Result<MaterializeResult, PeerSessionError> {
        if !matches!(
            planned,
            NativePlannedNode::Entry { .. } | NativePlannedNode::ExplicitDirectory { .. }
        ) {
            return Ok(MaterializeResult::RetryRequired);
        }
        self.materialize_head_under(
            group_id,
            target_path,
            &Election::Native { expected: planned },
            policy,
            satisfied,
            claim,
            OwnCaptureRule::RecaptureFirst,
        )
        .await
    }

    /// The node native's plan puts at `target_path` now, when there is one.
    pub(crate) fn native_planned_node(
        &self,
        group_id: &str,
        target_path: &str,
    ) -> Result<Option<NativePlannedNode>, PeerSessionError> {
        // Only the node at the path: a directory of thousands of siblings is not re-planned for
        // each of them. The plan is still computed now, from the database, under the caller's
        // path lock.
        self.state
            .native_plan_node(group_id, target_path)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The re-election under the path lock: the
    /// plan is recomputed and `expected` is projected only when the plan still
    /// puts exactly that node at `target_path`. A different node -- another
    /// head, another placement, another source, so another demand and another
    /// prefetch -- is not this call's to write; the next pass plans it whole.
    async fn elect_native_under_lock(
        &self,
        group_id: &str,
        target_path: &str,
        expected: &NativePlannedNode,
    ) -> Result<Option<Head>, PeerSessionError> {
        let fresh = self.native_planned_node(group_id, target_path)?;
        if fresh.as_ref() != Some(expected) {
            yadorilink_peer_session::dst_trace(target_path, || {
                format!(
                    "stale native materialize declined on {}: the plan no longer puts this node here",
                    self.local_device_id
                )
            });
            return Ok(None);
        }
        let (NativePlannedNode::Entry { head, .. } | NativePlannedNode::ExplicitDirectory { head }) =
            expected
        else {
            return Ok(None);
        };
        // Under the path lock: what this path gives up lives on at another
        // path, and is on disk there.
        let planned = matches!(expected, NativePlannedNode::Entry { .. }).then(|| head.version());
        if !self.displacement_allowed(group_id, target_path, planned.as_ref()).await? {
            return Ok(None);
        }
        Ok(Some(Head::of_native(head)))
    }

    /// See [`ReplicaCoordinator::finish_matching_in_flight_write`]; `false` means the caller
    /// retries instead of settling.
    fn finish_matching_in_flight_write(
        &self,
        group_id: &str,
        target_path: &str,
        version_hash: &yadorilink_replica_domain::ids::VersionHash,
        out_path: &Path,
    ) -> Result<bool, PeerSessionError> {
        let authority = self.root_lease_for(group_id)?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        self.state
            .finish_matching_in_flight_write(
                group_id,
                target_path,
                version_hash,
                yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(out_path).ok(),
                &permit,
            )
            .map_err(|error| PeerSessionError::from(crate::sync_error::SyncError::from(error)))
    }

    async fn recapture_instead_of_projecting(
        &self,
        group_id: &str,
        target_path: &str,
        head: &Head,
        election: &Election<'_>,
    ) -> Result<Recapture, PeerSessionError> {
        yadorilink_peer_session::dst_trace(target_path, || {
            format!(
                "own capture {} not written back on {}: disk moved on, recapturing",
                head.short_identity(),
                self.local_device_id,
            )
        });
        let flushed =
            self.pending_local_change_flush.capture_local_path_state(group_id, target_path).await;
        if flushed == PendingLocalFlushOutcome::RetryRequired {
            tracing::info!(
                group_id,
                path = target_path,
                "declined to project this device's own captured change over newer local state; \
                 the newer state could not be captured yet (still changing)"
            );
            return Ok(Recapture::StillChanging);
        }
        let still_elected = match election {
            Election::Native { .. } => {
                matches!(
                    self.native_planned_node(group_id, target_path)?,
                    Some(NativePlannedNode::Entry { head: entry, .. } | NativePlannedNode::ExplicitDirectory { head: entry })
                        if NativeRowIdentity::of(&entry) == head.identity
                )
            }
        };
        if still_elected {
            tracing::warn!(
                group_id,
                path = target_path,
                head = %head.short_identity(),
                "disk no longer holds this device's own captured change, but capturing the path \
                 authored nothing newer: capture finds no local state it has not recorded"
            );
            return Ok(Recapture::NothingNewer);
        }
        tracing::info!(
            group_id,
            path = target_path,
            "declined to project this device's own captured change over newer local state; \
             captured the newer state, which supersedes it"
        );
        Ok(Recapture::Superseded)
    }

    // The public entry point's parameters plus the recapture rule it runs
    // under; bundling them would only rename the same list.
    #[allow(clippy::too_many_arguments)]
    #[allow(
        clippy::too_many_lines,
        reason = "one native head's projection, from version lookup through recapture to \
              the proof, as a single ordered sequence sharing one permit"
    )]
    async fn materialize_head_under(
        &self,
        group_id: &str,
        target_path: &str,
        election: &Election<'_>,
        policy: MaterializationPolicy,
        satisfied: Option<&BlockRequirement>,
        claim: Option<super::obligation_claims::PathClaim<'_>>,
        own_capture_rule: OwnCaptureRule,
    ) -> Result<MaterializeResult, PeerSessionError> {
        let activity_provider = self.block_write_activity_provider();
        let _write_activity = activity_provider.begin_block_write_activity();
        // Flush any same-path (and case-fold sibling) local edit still sitting
        // in this link's debounce accumulator *before* taking the path lock —
        // the same ordering the legacy reconcile relies on so a not-yet-indexed
        // local write is captured (into the index and native state) rather than
        // silently overwritten by this materialize.
        let flush_started = std::time::Instant::now();
        let flushed = self.flush_local_changes_before_reconcile(group_id, target_path).await;
        let flush_elapsed = flush_started.elapsed();
        crate::receive_diag::mark(crate::receive_diag::Stage::Flushed);
        if flushed == PendingLocalFlushOutcome::RetryRequired {
            // A local edit at this path could not be captured -- most often
            // a file still being written. Writing now would put this
            // device's older view of the path over bytes it never
            // authored. Leave the obligation for a later pass; the capture
            // that eventually succeeds moves the path's head anyway.
            yadorilink_peer_session::dst_trace(target_path, || {
                format!(
                    "materialize deferred on {}: pending local edit not captured",
                    self.local_device_id
                )
            });
            return Ok(MaterializeResult::RetryRequired);
        }
        // Held across the whole materialize (including its block-fetch awaits),
        // closing the local-save-vs-incoming-version race exactly as the legacy
        // path does.
        let lock_wait_started = std::time::Instant::now();
        let path_lock = self.state.path_lock(group_id, target_path);
        let _guard = crate::receive_diag::lock_path(&path_lock).await;
        let lock_wait_elapsed = lock_wait_started.elapsed();
        crate::receive_diag::mark(crate::receive_diag::Stage::Locked);
        if flush_elapsed > std::time::Duration::from_secs(1)
            || lock_wait_elapsed > std::time::Duration::from_secs(1)
        {
            tracing::warn!(
                group_id,
                path = target_path,
                flush_elapsed_ms = flush_elapsed.as_millis(),
                lock_wait_elapsed_ms = lock_wait_elapsed.as_millis(),
                "materialize_dag_content_head flush/lock-wait took unusually long"
            );
        }
        // The freshness principle applied INSIDE the path lock: the
        // resolution that elected `head` ran before this lock was acquired,
        // and a newer change for this path can land in between — most
        // dangerously this device's OWN local tombstone (a user deleting or
        // renaming the file away), whose emission removes the file, writes
        // the deleted index row, and admits the change already `applied`.
        // Writing the pre-lock winner anyway resurrects content the newer
        // change just removed on this very device, and because a locally
        // authored change is never reprojected, nothing re-examines the path
        // afterwards — captured live (single-path DST trace, three-device
        // mesh chaos seed 1000005) as a deterministic terminal divergence:
        // the device that authored a rename's tombstone re-materialized the
        // pre-rename winner an instant later and kept, forever, a live file
        // every peer had deleted, under byte-identical native heads. Re-resolve
        // under the lock (with the caller's derived-copy context, so a
        // fixpoint-derived conflict copy re-validates against the same
        // inputs that elected it) and decline a head that is no longer the
        // current winner; `RetryRequired` keeps the caller from recording
        // the path as settled on the strength of a write that did not
        // happen, and whichever change superseded `head` drives (or already
        // drove) the path's real projection through its own admission.
        let projected = match election {
            Election::Native { expected } => {
                match self.elect_native_under_lock(group_id, target_path, expected).await? {
                    Some(projected) => projected,
                    None => return Ok(MaterializeResult::RetryRequired),
                }
            }
        };
        let version_hash = projected.version_hash;
        let Some(version) = self.state.dag_get_file_version(group_id, &version_hash)? else {
            // Admission gated on the version being present, so this only
            // happens if it was pruned in between — skip; a later heads
            // exchange re-drives this path once the version is re-supplied.
            // NOT settled: content was never verified/written, so a caller
            // must not treat this as done (see `MaterializeResult`'s own
            // doc comment).
            tracing::warn!(
                group_id,
                path = target_path,
                version = %version_hash.to_hex(),
                "file version for a resolved content head is missing; skipping materialize"
            );
            return Ok(MaterializeResult::RetryRequired);
        };
        let record = file_record_from_version(target_path, &version);
        let projected_authoring = Some(projected.authoring().clone());
        let columns =
            yadorilink_replica_domain::session_state::LocalFileMetaColumns::from_version_meta(
                &version.meta,
            );
        // If this path already holds exactly this version's content, there is
        // nothing to fetch or rewrite. Skipping here matters beyond saving
        // work: re-running the projection, or resolving to a version this
        // device itself authored, must not overwrite an existing, richer index
        // row (real version vector, real per-block sizes) with the projection's
        // placeholder metadata.
        //
        // A plain regular file gets a richer classification
        // than symlink/directory records below -- not just "is the content
        // already right" (which still costs two writer_gate acquisitions
        // even on a genuine no-op re-examination: one for the metadata
        // columns, one for the full row upsert), but "is EVERYTHING already
        // right" (content, row identity, authoring, origin), in which case
        // this candidate costs zero DB writes at all. Content-identical
        // re-examination dominates writer_gate load under a large change
        // burst once ordinary batching removes the bigger per-path write
        // sources, and most of those re-examinations are genuinely fully
        // settled, not merely content-identical. Scoped to `RecordKind::
        // File` only -- symlink/directory records keep the exact prior
        // behavior below, matching every other scoping choice in
        // this file (placeholder/hazard/conflict-copy stay on the existing
        // path too).
        // Before any "is this already materialized?" shortcut below, and
        // before any write: a name this device refuses to write is held,
        // and holding it is a durable outcome, not a reason to skip the
        // path silently.
        //
        // The order matters specifically on a case-insensitive volume, and
        // getting it wrong was a real, reproduced defect (confirmed on real
        // APFS): every shortcut below asks its question by opening
        // `sync_root/target_path`, which such a volume resolves to whatever
        // existing file case-folds to that name -- a DIFFERENT file than
        // the record being materialized. Consulting it at all for a
        // colliding name means deciding this record's fate by inspecting
        // another record's bytes, and the observed effect was that an
        // incoming "photo.jpg" colliding with an already-materialized
        // "Photo.jpg" was reported `Settled` -- marked converged, with no
        // hold ever recorded, so nothing re-examined it and the collision
        // was silently forgotten. (The first file's content was correctly
        // left intact throughout; the damage was to the bookkeeping, not
        // the data.)
        //
        // `prepare_ordinary_projected_upsert`'s own hazard check stays a
        // pure batch-eligibility test that declines to batch: this is the
        // path that decides what actually happens to a hazardous record,
        // and the batched route defers here precisely so there is one such
        // place rather than two.
        if let Some(reason) = self.hazard_reason_for(group_id, &record).await? {
            let authority = self.root_lease_for(group_id)?;
            let authority_op = authority.begin_operation()?;
            let permit = authority_op.permit();
            hold_record(
                self.state.as_ref(),
                group_id,
                &record,
                &reason,
                &projected.device_id,
                projected_authoring.as_ref(),
                &columns,
                &permit,
            )?;
            // Durable: `hold_record` upserts the incoming record with its
            // own authoring identity, so this projection is genuinely
            // concluded rather than owed another attempt. The path is
            // re-examined when the hazard itself clears, through the
            // hazard-recheck sweep, not by re-driving this change.
            //
            // `HazardHeld`, not `ExactAbsent`. This lane used to claim
            // exact absence for a path `hold_record` had just given a
            // live, non-deleted row with a `held_reason` -- the opposite
            // of absent. The engine published that as an exact `Absent`
            // proof and then closed the obligation through the exact
            // completion, which checks the proof's hash and the
            // obligation's generation but never asks the `files` row
            // whether the path is really a tombstone. So a held path
            // settled as proven-absent.
            //
            // `materialize()`'s own three hazard branches have always
            // returned `HazardHeld`, and the engine's non-exact
            // completion re-checks `held_reason IS NOT NULL` inside its
            // own transaction. That is the route this lane belongs on.
            //
            // The fence bump goes with it: a hold performs no physical
            // mutation, and this one existed only to carry an epoch for
            // the proof that should never have been published.
            return Ok(MaterializeResult::Settled(SettlementEvidence::HazardHeld { reason }));
        }
        if version.meta.record_kind == RecordKind::File {
            if let Some(current) = self.state.get_current_version_record(group_id, target_path)? {
                let blocks_match = !current.deleted
                    && current.blocks.len() == version.blocks.len()
                    && current
                        .blocks
                        .iter()
                        .zip(&version.blocks)
                        .all(|(b, vb)| b.hash == vb.hash.0);
                // Unlike the symlink/directory
                // branch below, a `RecordKind::File` with an empty block
                // list is a genuinely verifiable on-disk state (an existing,
                // exactly-empty regular file) -- `disk_bytes_match_indexed_
                // blocks` (via `disk_content_comparison`) correctly proves
                // that even for zero blocks (open the path, read zero
                // blocks, then require exactly zero trailing bytes), so
                // this branch must not take the "no content blocks to
                // verify" shortcut the symlink/directory branch legitimately
                // does. Skipping it here would let an index row survive a
                // local deletion of the underlying empty file the watcher/
                // debounce pipeline hasn't caught up to yet -- the old
                // path's own `try_apply_metadata_only_update` never had this
                // gap because it unconditionally rejected an empty block
                // list outright. A verification failure (including "file
                // vanished") falls through to the slow path below, same as
                // `blocks_match` being false.
                //
                // A file whose owner cannot read it has neither verifiable
                // bytes nor readable or settable replicated metadata. It is
                // held, before anything is mutated, rather than failing this
                // pass with a raw permission error or falling through to a
                // path that could replace it.
                let content_matches = blocks_match
                    && match yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                        &self.sync_root(group_id)?.join(target_path),
                        &record.blocks,
                    ) {
                        Ok(matches) => matches,
                        Err(yadorilink_local_storage::StorageError::Io(error))
                            if error.kind() == std::io::ErrorKind::PermissionDenied =>
                        {
                            let reason = self.state.hold_metadata_unprovable(
                                group_id,
                                target_path,
                                &self.sync_root(group_id)?.join(target_path),
                                &version_hash,
                            )?;
                            return Ok(MaterializeResult::Settled(
                                SettlementEvidence::HazardHeld { reason },
                            ));
                        }
                        Err(error) => return Err(error.into()),
                    };
                // This device's own capture of the path whose bytes still
                // match but whose mode or replicated attributes do not:
                // "repairing" them would write the captured metadata back
                // over a newer local edit, which capture records as one. It
                // is left to the recapture below, like a content change.
                let own_capture = own_capture_rule == OwnCaptureRule::RecaptureFirst
                    && projected.device_id == self.local_device_id
                    && self.state.is_local_capture_head(group_id, target_path, &projected)?;
                let content_matches = content_matches
                    && (!own_capture
                        || mode_and_xattrs_match_disk(
                            &self.sync_root(group_id)?.join(target_path),
                            &version,
                        )?);
                if content_matches {
                    // `current` was read as one atomic statement, so this
                    // reconstructs the exact `FileVersion` identity that row
                    // describes -- equal to `version_hash` iff every column
                    // `FileVersion` identity covers (blocks/size/mtime/
                    // record_kind/symlink_target/unix_mode/xattrs) already
                    // agrees. The native authoring identity, `origin_device_id` and
                    // `symlink_out_of_root` are not part of that identity,
                    // so they need their own checks to rule out a truly
                    // no-op DB write.
                    let index_fully_matches = current.to_file_version().version_hash
                        == version_hash
                        && self.state.row_authoring(group_id, target_path)? == projected_authoring
                        && self.state.get_origin_device_id(group_id, target_path)?.as_deref()
                            == Some(projected.device_id.as_str())
                        && self.state.get_symlink_out_of_root(group_id, target_path)?
                            == columns.symlink_out_of_root;
                    if !index_fully_matches {
                        let authority = self.root_lease_for(group_id)?;
                        let authority_op = authority.begin_operation()?;
                        let permit = authority_op.permit();
                        self.state.apply_projected_row_atomic(
                            group_id,
                            &record,
                            &projected.device_id,
                            projected_authoring.as_ref(),
                            &columns,
                            &permit,
                        )?;
                    }
                    // Never skipped, even when `index_fully_matches`: the DB
                    // matching the target version only proves the RECORDED
                    // mode/xattrs are right, not that the actual on-disk
                    // file's mode/xattrs still are (e.g. a local chmod this
                    // device's own watcher hasn't reconciled yet) -- keeping
                    // this repair semantics is why this is not a naive early
                    // return.
                    //
                    // Re-verify root identity
                    // and this path's containment immediately before these
                    // disk mutations, matching every other write path in
                    // this module (`self.verify_write_target` -- see its own
                    // doc comment) -- the block hashing above (`disk_bytes_
                    // match_indexed_blocks`) can take real time, and a root
                    // swap or an intermediate-symlink substitution during
                    // that window must not go undetected right up to the
                    // point this function mutates whatever is now at
                    // `out_path`.
                    let out_path = self.sync_root(group_id)?.join(target_path);
                    self.verify_write_target(group_id, &out_path)?;
                    // See
                    // `terminal_object_is_a_regular_file`'s own doc
                    // comment: `verify_write_target` only confirms the
                    // PARENT directory chain, and every call below this
                    // point follows a terminal symlink. Refuse to settle
                    // this fast path at all rather than chmod/xattr-ing
                    // through a symlink this branch never checked for --
                    // a later tick re-resolves from scratch, and the
                    // ordinary reconstruct path it may then take is the
                    // temp-then-rename primitive, which is safe.
                    if !terminal_object_is_a_regular_file(&out_path) {
                        return Ok(MaterializeResult::RetryRequired);
                    }
                    // `apply_unix_mode`/`apply_xattrs` are NOT a cheap no-op
                    // when nothing has actually drifted: `apply_xattrs` unconditionally issues a real
                    // `fsetxattr` for every desired name regardless of
                    // whether the value already matches, which the mutation
                    // fence's own "bump before the first mutating syscall"
                    // invariant treats as a real mutation -- the same class
                    // of gap `try_apply_metadata_only_update` handles.
                    // Determine first, then decide snapshot vs. bump, mirroring
                    // that function exactly.
                    // See `try_apply_metadata_only_update`'s identical
                    // handling for why mtime must be folded into this same
                    // decision -- a same-content, mtime-only-changed
                    // version must still attempt the stamp (mtime is
                    // retained-only, never blocking, but not "never even
                    // attempted" either), and attempting it is a real
                    // mutating syscall needing the same preceding bump.
                    let mode_and_xattrs_match = mode_and_xattrs_match_disk(&out_path, &version)?;
                    // An own capture whose mode or attributes moved on never
                    // got here (see `content_matches` above). An mtime that
                    // alone differs is not an edit capture records, and not
                    // that change's to undo either: it is left as it is,
                    // and mtime is retained-only in the settlement.
                    let metadata_already_matches_disk = mode_and_xattrs_match
                        && (own_capture
                            || yadorilink_local_storage::mtime_already_matches_disk(
                                &out_path,
                                version.meta.mtime_unix_nanos,
                            )?);
                    let (mutation_generation, xattr_evidence) = if metadata_already_matches_disk {
                        // This path's bytes were verified (not written)
                        // identical to the desired version above
                        // (`content_matches`), and metadata already matches
                        // too -- a genuine *snapshot*, never a bump, since
                        // no mutating syscall occurs here. Nothing written,
                        // so the xattrs are proved from disk.
                        (
                            self.state.dag_snapshot_mutation_fence(group_id, target_path)?,
                            XattrEvidence::ReproveFromDisk,
                        )
                    } else {
                        let fence = self.state.dag_bump_mutation_fence(
                            group_id,
                            target_path,
                            "metadata_repair",
                        )?;
                        // Before the final mode, which may deny the owner
                        // the read access the stamp's open needs.
                        yadorilink_local_storage::stamp_mtime_at_path(
                            &out_path,
                            version.meta.mtime_unix_nanos,
                        )?;
                        let applied = yadorilink_local_storage::apply_file_metadata_verified(
                            &out_path,
                            version.meta.unix_mode,
                            &version.meta.xattrs,
                        )?;
                        (fence, XattrEvidence::from(applied))
                    };
                    require_xattr_evidence(
                        target_path,
                        &out_path,
                        &version.meta.xattrs,
                        &xattr_evidence,
                    )?;
                    // A path held because its file was unreadable settles
                    // here once it is readable again; the hold goes with it.
                    self.state.clear_metadata_unprovable_hold(group_id, target_path)?;
                    // The bytes are the version's, but the row may still be the
                    // unfinished write that put them there: an earlier attempt
                    // renamed the file in and was refused at its commit (another
                    // mutator advanced the fence), leaving the row in flight with
                    // its intent open and no proof. Settling now would report the
                    // path done, and what closes an obligation on the strength of
                    // this settlement -- or, for a conflict copy, nothing at all,
                    // since a copy owns no obligation -- would leave it unproven
                    // for good. Finish it the way the repair sweep finishes a
                    // write whose bytes are already right: one guarded commit.
                    if !self.finish_matching_in_flight_write(
                        group_id,
                        target_path,
                        &version_hash,
                        &out_path,
                    )? {
                        return Ok(MaterializeResult::RetryRequired);
                    }
                    return Ok(MaterializeResult::Settled(SettlementEvidence::ExactObject {
                        kind: RecordKind::File,
                        version: version_hash,
                        identity: Box::new(
                            yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(
                                &out_path,
                            )
                            .ok(),
                        ),
                        mutation_generation,
                    }));
                }
            }
        } else if let Some(local) = self.state.get_file(group_id, target_path)? {
            let same_content = !local.deleted
                && local.blocks.len() == version.blocks.len()
                && local.blocks.iter().zip(&version.blocks).all(|(b, vb)| b.hash == vb.hash.0);
            // The index alone is not proof the fast path is safe: it only
            // means this device's LAST INDEXING pass produced a record whose
            // block list happens to match the winner's. A raw filesystem
            // write to this same path (e.g. a concurrent local edit) changes
            // the actual bytes on disk immediately, but is only reflected in
            // the index once the watcher/debounce pipeline processes it —
            // which can lag behind an incoming remote materialize attempt
            // that runs in the meantime. Trusting a stale index here would
            // silently skip the real write, permanently leaving the wrong
            // bytes on disk with the index and native state both agreeing the path is
            // "done" — nothing else would ever re-examine it. Verify actual
            // disk bytes hash-match the winner's blocks before trusting this
            // fast path; skip the check only for record kinds with no
            // content blocks to verify (symlink/directory), where it would
            // be meaningless (and `disk_bytes_match_indexed_blocks` assumes
            // a regular file). A verification failure (including "file
            // vanished") falls through to the real write below, same as
            // `same_content` being false to begin with.
            let same_content = same_content
                && (version.blocks.is_empty()
                    || yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                        &self.sync_root(group_id)?.join(target_path),
                        &record.blocks,
                    )?);
            if same_content {
                // Content equality does not imply version equality: exec-bit,
                // symlink, or mtime-only changes are part of FileVersion
                // identity, so native state winner's metadata still has to be
                // applied here. Returning without this step leaves replicas
                // with the same bytes but permanently divergent permissions.
                // The update writes it with the new version's row; the row
                // of the version it replaces is left as it was authored.
                let metadata_record = record.clone();
                let authority = self.root_lease_for(group_id)?;
                let authority_op = authority.begin_operation()?;
                let permit = authority_op.permit();
                // The version is already known here -- it came from the
                // projection being applied -- so this site never had the
                // re-inference problem. It takes the generation and
                // ignores the helper's own reading of the row.
                let update = match try_apply_metadata_only_update(
                    self.state.as_ref(),
                    &self.sync_root(group_id)?,
                    group_id,
                    &metadata_record,
                    &projected.device_id,
                    projected_authoring.as_ref(),
                    // The projection's own resolved version -- the same
                    // one this metadata came from.
                    &version,
                    &permit,
                ) {
                    // See the regular-file branch above: held, not retried.
                    Err(PeerSessionError::MetadataUnprovable(_)) => {
                        let reason = self.state.hold_metadata_unprovable(
                            group_id,
                            target_path,
                            &self.sync_root(group_id)?.join(target_path),
                            &version_hash,
                        )?;
                        return Ok(MaterializeResult::Settled(SettlementEvidence::HazardHeld {
                            reason,
                        }));
                    }
                    other => other?,
                };
                if let Some(MetadataOnlyUpdate { mutation_generation, .. }) = update {
                    // `try_apply_metadata_only_update` itself already
                    // decided snapshot vs. bump based on whether applying
                    // metadata actually changed anything on disk -- see its
                    // own doc comment.
                    let out_path = self.sync_root(group_id)?.join(target_path);
                    return Ok(MaterializeResult::Settled(SettlementEvidence::ExactObject {
                        kind: version.meta.record_kind,
                        version: version_hash,
                        identity: Box::new(
                            yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(
                                &out_path,
                            )
                            .ok(),
                        ),
                        mutation_generation,
                    }));
                }
            }
        }
        // Everything above that could settle this path without writing it
        // has declined: disk does not hold this head. For this device's own
        // capture of the path that means disk moved on after the capture --
        // other bytes, another link target, or no file at all -- and what
        // is there is newer local state. Writing the capture back would
        // destroy it (or bring back a file the user deleted), and merely
        // retrying would leave the older change standing as the path's head
        // with nothing to supersede it. Capture the disk instead, its
        // absence included -- outside the path lock, which capture takes
        // itself -- so the newer state becomes a newer change and this
        // obligation is superseded by it. A file still changing is left for
        // a later pass by the same capture.
        //
        // Capture compares disk with the index row, not with this head, so
        // it can find nothing newer to author: disk holds what this device
        // last recorded for the path, and there is no uncaptured local
        // state to protect. The path is then projected exactly as it was
        // before this rule existed, from the top (the lock was released for
        // the capture), rather than declined on every pass. A deletion is
        // the exception: bringing a file back is never that projection's to
        // make, so it waits for the watcher's own capture of it.
        let on_disk = match own_capture_rule {
            OwnCaptureRule::RecaptureFirst => {
                self.own_capture_on_disk(group_id, target_path, &projected, &version)?
            }
            OwnCaptureRule::ProjectAsBefore => OwnCaptureOnDisk::NotACapture,
        };
        if on_disk.superseded() {
            drop(_guard);
            return match self
                .recapture_instead_of_projecting(group_id, target_path, &projected, election)
                .await?
            {
                Recapture::NothingNewer if on_disk != OwnCaptureOnDisk::Removed => {
                    Box::pin(self.materialize_head_under(
                        group_id,
                        target_path,
                        election,
                        policy,
                        satisfied,
                        claim,
                        OwnCaptureRule::ProjectAsBefore,
                    ))
                    .await
                }
                _ => Ok(MaterializeResult::RetryRequired),
            };
        }
        // Return `materialize`'s own result unchanged: it reports
        // `RetryRequired` for every "not done yet" shape (blocks not
        // fetchable this attempt, decline under the path lock, or a
        // hazardous TOMBSTONE holding a genuine live row rather than
        // deleting it — see the `if record.deleted` branch's own doc
        // comment for why that specific case is not durable), and
        // collapsing any of those to `Settled` here marks the change
        // applied with content that never landed — a live index row with
        // no file on disk that nothing ever re-examines. A CREATE/symlink
        // hazard hold for a content record like this one is different:
        // `hold_record` fully upserts the incoming record (including its
        // own authoring identity), so that case is a genuinely durable
        // `Settled` outcome, not one this comment needs to call out. The
        // authoring identity needs no follow-up write either: `materialize`
        // persists it atomically with the row in every branch that writes
        // one.
        // `satisfied` is what the pre-pass observed for this path before the
        // blocks were requested, so the racing-local-write guard still has
        // something to compare against, and so a path whose content never
        // arrived records its retriable placeholder rather than asking again.
        // A path with no entry -- one that appeared after the pass was planned
        // -- is left unsettled for the next one.
        // The version that resolved this head IS the payload's version --
        // the record above is derived from it. Nothing here reads the row
        // to find out what is being written.
        let payload = MaterializationPayload::from_version(target_path, version.clone());
        match self
            .materialize_local(
                group_id,
                &payload,
                policy,
                &projected.device_id,
                projected_authoring.as_ref(),
                satisfied,
                claim,
            )
            .await?
        {
            LocalMaterializeOutcome::Concluded(result) => Ok(result),
            LocalMaterializeOutcome::NeedBlocks(_) => Ok(MaterializeResult::RetryRequired),
        }
    }
}
