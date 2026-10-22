//! Owner operations for the daemon's convergence lanes.
//!
//! Each method is the "open" half of a lane's protocol: the durable steps
//! that run before the lane's physical write. The write itself, and every
//! lane check between these steps and the write (target verification,
//! preflight, and for most lanes the fence bump that follows it), stay in
//! the lane.

use std::sync::Arc;

use yadorilink_filesystem_sync::materialization_execution::MaterializationIntentKind;
use yadorilink_peer_session::ports::OpenMaterializationIntent;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};

use super::super::ReplicaCoordinator;

/// Resolves the root lease a row persist starts its own, fresh root
/// operation under. Called at the moment of the persist, never earlier:
/// a link that stops after the intent opened must still refuse the row.
pub(crate) type RowAuthority<'a> =
    &'a (dyn Fn() -> Result<Arc<RootLease>, PeerSessionError> + Sync);

/// A materialization intent a lane holds across its physical write.
pub(crate) type LaneIntent<'a> = Box<dyn OpenMaterializationIntent + Send + 'a>;

/// The target a tombstone delete's intent names. A delete has no content to
/// name, so the target is a marker, and one no content can have: every
/// content target is a 32-byte SHA-256, this is not 32 bytes. The hash of
/// an empty block list would not do, since that is also the ordinary target
/// of an empty file. Only this module reads or writes it; everything else
/// sees [`MaterializationIntentKind`].
const TOMBSTONE_DELETE_INTENT_TARGET: &[u8] = b"yadorilink:tombstone-delete";

impl ReplicaCoordinator {
    /// Writes `record` into the index with its origin, and its authoring
    /// identity when one is known, under a root operation begun from
    /// `row_authority` right now, in its own transaction.
    pub(crate) fn persist_row_under_fresh_operation(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: Option<&yadorilink_replica_domain::session_state::LocalFileMetaColumns>,
        row_authority: RowAuthority<'_>,
    ) -> Result<(), PeerSessionError> {
        let authority = row_authority()?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        self.upsert_file_with_origin_and_authoring(
            group_id,
            record,
            origin_device_id,
            authoring,
            meta,
            &permit,
        )
    }

    /// The journaled row commit every regular-file write opens with:
    /// durably open this record's materialization intent (tx), then commit
    /// its row under a fresh root operation (tx), so a crash between the
    /// row and the file never leaves an indexed path with no file and no
    /// intent.
    // One argument per input of the persisted row.
    #[allow(clippy::too_many_arguments)]
    fn open_intent_and_persist_row<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        row_authority: RowAuthority<'_>,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<LaneIntent<'a>, PeerSessionError> {
        let intent_target_hash = yadorilink_local_storage::intent_target_hash(&record.blocks);
        let intent_guard = self.open_materialization_intent_guard(
            group_id,
            &record.path,
            &intent_target_hash,
            permit,
        )?;
        self.persist_row_under_fresh_operation(
            group_id,
            record,
            origin_device_id,
            authoring,
            Some(meta),
            row_authority,
        )?;
        Ok(intent_guard)
    }

    /// Open half of the eager content write, in ONE transaction, in
    /// this order: open the intent, persist the row, mark the row in flight,
    /// clear any hazard hold, and bump the path's mutation fence. Returns the
    /// fence value the write's proof will CAS on and the intent the lane
    /// holds across the write. The lane runs its target checks and writes
    /// after this commits.
    ///
    /// What the single commit guarantees, each part of it load-bearing:
    ///
    /// - The intent is durable before the first disk mutation, and in the
    ///   same commit as the row. A crash after this commit and before the
    ///   temp file exists leaves "row in flight, no file, intent open",
    ///   which repair rebuilds from the blocks instead of reading it as an
    ///   offline delete. No crash can leave the row without the intent.
    /// - The fence bump is durable before the disk write. A local edit or a
    ///   capture that lands after this commit bumps the fence again, so the
    ///   proof's CAS on the value returned here fails and nothing is
    ///   published for bytes that may be stale.
    /// - A step that fails rolls every earlier one back: there is either no
    ///   intent, row, state or fence change at all, or all of them.
    /// - The commit runs on the blocking pool while the caller's task keeps
    ///   polling its siblings (unless `YADORILINK_RECEIVE_ASYNC_COMMIT=0`).
    ///   The caller's frames (path lock, lane operation, claim) and this
    ///   frame (the row's operation) stay alive until the outcome is
    ///   decided, even when the awaiting task is dropped mid-commit: see
    ///   `SyncDatabase::write_immediate_offloaded`.
    /// - Both permits are re-verified inside the transaction, immediately
    ///   before it commits: the lane's, and the one of the fresh root
    ///   operation the row is committed under, begun from `row_authority`
    ///   only now, so a link that stopped after the lane began commits
    ///   nothing.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_content_write<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        row_authority: RowAuthority<'_>,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<(i64, LaneIntent<'a>), PeerSessionError> {
        self.open_content_write_via(
            group_id,
            record,
            origin_device_id,
            authoring,
            meta,
            row_authority,
            permit,
            |open| self.commit_open_single(open),
        )
        .await
    }

    /// [`Self::open_content_write`] with the commit of the open transaction
    /// supplied by the caller: `commit` receives the owned open and returns
    /// the fence value once the open is decided, however it commits it (alone
    /// on the blocking pool, or queued with the run's other files in one
    /// batch, `Self::open_content_writes`).
    ///
    /// This frame holds the row's own root operation until `commit` has
    /// returned, and the caller's frames hold the lane's operation and the
    /// path lock: `commit` gets only owned data and the two owned root
    /// checks, which re-verify root identity but hold no stop lease.
    // Each argument is an independent input to the one open.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_content_write_via<'a, F, Fut>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        row_authority: RowAuthority<'_>,
        permit: &'a RootCommitPermit<'a>,
        commit: F,
    ) -> Result<(i64, LaneIntent<'a>), PeerSessionError>
    where
        F: FnOnce(OwnedContentWriteOpen) -> Fut,
        Fut: std::future::Future<Output = Result<i64, PeerSessionError>>,
    {
        // The row's own root operation lives in this frame, so it is held
        // until the commit below has been decided, including when the commit
        // runs on the blocking pool: the stop fence is the operation's, the
        // owned checks only re-verify root identity. The lane's operation is
        // held by the caller's frames for the same reason.
        let authority = row_authority()?;
        let authority_op = authority.begin_operation()?;
        let row_permit = authority_op.permit();
        let open = OwnedContentWriteOpen {
            group_id: group_id.to_owned(),
            record: record.clone(),
            origin_device_id: origin_device_id.to_owned(),
            authoring: authoring.cloned(),
            meta: meta.clone(),
            intent_target_hash: yadorilink_local_storage::intent_target_hash(&record.blocks),
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0),
            lane_check: permit.owned_check(),
            row_check: row_permit.owned_check(),
            #[cfg(test)]
            gate: self
                .test_observers
                .open_commit_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            #[cfg(test)]
            gate_fired: std::sync::atomic::AtomicBool::new(false),
        };
        let mutation_generation = commit(open).await?;
        // After the row has landed, as for every other upsert a lane makes.
        #[cfg(test)]
        self.test_observers.fire_armed_upsert_supersession(group_id, &record.path);
        let intent: LaneIntent<'a> =
            Box::new(crate::materialization_intent::MaterializationIntentGuard::opened(
                self,
                group_id,
                &record.path,
                permit,
            ));
        Ok((mutation_generation, intent))
    }

    /// The open of one file in a transaction of its own: on the blocking pool
    /// (the awaiting future holds a job fence, see
    /// `SyncDatabase::write_immediate_offloaded`) or, with
    /// `YADORILINK_RECEIVE_ASYNC_COMMIT=0`, inline in this poll.
    pub(crate) async fn commit_open_single(
        &self,
        open: OwnedContentWriteOpen,
    ) -> Result<i64, PeerSessionError> {
        let commit = move |tx: &rusqlite::Transaction<'_>| open.run_in_tx(tx);
        let outcome = if self.async_commit() {
            self.database
                .write_immediate_offloaded::<_, yadorilink_sync_sqlite::SyncSqliteError>(commit)
                .await
        } else {
            self.database.write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(commit)
        };
        Ok(outcome.map_err(crate::sync_error::SyncError::from)?)
    }

    /// [`Self::commit_open_single`] for several files in ONE transaction (see
    /// `yadorilink_sync_sqlite::content_write_open::open_content_writes_in_tx`):
    /// each item has the same statements, its own savepoint and its own two
    /// root checks. One item's failure is that item's outcome; the outer
    /// result is an error only when the transaction failed or a root stopped
    /// being this link's, in which case nothing was written.
    ///
    /// The caller owns the guards of every item (its path lock, the lane's
    /// and the row's root operations) and holds them until the item's
    /// outcome has been handed back.
    pub(crate) fn open_content_writes(
        &self,
        items: &[&OwnedContentWriteOpen],
    ) -> Result<Vec<Result<i64, PeerSessionError>>, PeerSessionError> {
        use yadorilink_sync_sqlite::content_write_open::{
            open_content_writes_in_tx, OpenWriteRequest,
        };
        #[cfg(test)]
        {
            let gate = self
                .test_observers
                .open_batch_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if let Some(gate) = gate {
                gate();
            }
        }
        let requests: Vec<OpenWriteRequest<'_>> = items.iter().map(|item| item.request()).collect();
        let outcomes = self
            .database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                let outcomes =
                    open_content_writes_in_tx(tx, &requests, |index| items[index].verify_roots())?;
                #[cfg(test)]
                {
                    self.test_observers
                        .open_batch_sizes
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(items.len());
                    if self
                        .test_observers
                        .open_batch_fails_before_commit
                        .load(std::sync::atomic::Ordering::SeqCst)
                    {
                        return Err(yadorilink_sync_sqlite::SyncSqliteError::CorruptState(
                            "injected failure before the batch commits".into(),
                        ));
                    }
                }
                Ok(outcomes)
            })
            .map_err(crate::sync_error::SyncError::from)?;
        Ok(outcomes
            .into_iter()
            .map(|outcome| {
                outcome.map_err(crate::sync_error::SyncError::from).map_err(PeerSessionError::from)
            })
            .collect())
    }

    /// Close half of the eager content write, in ONE transaction: under the
    /// fence [`Self::open_content_write`] bumped, and only while the row is
    /// still in flight at `written`'s version, publish the proof of the
    /// written file, stamp the row `Present` and clear the intent; then,
    /// when the obligation engine holds a claim on the path, close its
    /// obligation under that claim. The lane calls this only once the bytes
    /// are durable: temp file synced, renamed into place, parent directory
    /// synced, metadata applied and verified.
    ///
    /// What the single commit guarantees:
    ///
    /// - Nothing is published or completed before the bytes are durable,
    ///   because nothing of it is written before this call.
    /// - A fence that moved after the open (a capture, a local edit, any
    ///   other mutator) or a row superseded by a newer version refuses the
    ///   whole commit: no proof, no stamp, the intent and the obligation
    ///   left open, so the write is re-driven. A refused proof never leaves
    ///   anything behind that describes the bytes.
    /// - The claim's generation and incarnation are checked in this same
    ///   transaction, by the same completion statement every exact close
    ///   uses; that statement also requires the proof just published here.
    ///   A claim a newer admission or a re-arm overtook closes nothing, and
    ///   the proof still commits: it is exactly true on its own (see
    ///   `commit_internal_materialized_state_closing_obligation`), and the
    ///   open obligation is closed by the next claim with no physical work.
    /// - A crash before this commit leaves the intent and the obligation
    ///   open over durable bytes; startup repair finishes the bookkeeping
    ///   and the next claim closes the obligation. A crash after it leaves
    ///   nothing to do.
    /// - The lane's permit is re-verified inside the transaction, so a root
    ///   lost since the write publishes nothing.
    ///
    /// The proof's causal basis is the group's heads read in this
    /// transaction, as for the fenced commit on its own; no separate
    /// publication follows.
    // Each argument is an independent input to the one commit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn close_content_write(
        &self,
        group_id: &str,
        path: &str,
        exact_state: &yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState,
        expected_mutation_generation: i64,
        expected_authoring: yadorilink_sync_sqlite::exact_materialized_commit::ExpectedAuthoring<
            '_,
        >,
        claim: Option<yadorilink_sync_sqlite::projection_obligations::ObligationClaimToken>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<ContentWriteClose, PeerSessionError> {
        use yadorilink_sync_sqlite::exact_materialized_commit::{
            commit_internal_materialized_state_closing_obligation,
            commit_internal_materialized_state_if_fence_current,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let (commit, obligation_closed) = self
            .database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                let outcome = match claim {
                    Some(claim) => commit_internal_materialized_state_closing_obligation(
                        tx,
                        group_id,
                        path,
                        exact_state,
                        expected_mutation_generation,
                        Some(expected_authoring),
                        claim,
                        now,
                    )?,
                    None => (
                        commit_internal_materialized_state_if_fence_current(
                            tx,
                            group_id,
                            path,
                            exact_state,
                            expected_mutation_generation,
                            Some(expected_authoring),
                            now,
                        )?,
                        false,
                    ),
                };
                permit.verify()?;
                Ok(outcome)
            })
            .map_err(crate::sync_error::SyncError::from)?;
        let (close, obligation_closed) = Self::describe_content_write_close(
            group_id,
            path,
            expected_mutation_generation,
            claim,
            commit,
            obligation_closed,
        );
        if obligation_closed {
            // A write just made durable can be the sibling change that
            // clears a held path's hazard.
            self.hazard_recheck_wake().mark_dirty(group_id);
        }
        Ok(close)
    }

    /// What one close's commit means for its file, and whether it closed the
    /// path's obligation (the caller wakes the retirement and hazard workers
    /// for that). Logs the refusals and the overtaken claim. Shared by the
    /// single-file and the batched close so both report identically.
    fn describe_content_write_close(
        group_id: &str,
        path: &str,
        expected_mutation_generation: i64,
        claim: Option<yadorilink_sync_sqlite::projection_obligations::ObligationClaimToken>,
        commit: yadorilink_sync_sqlite::exact_materialized_commit::InternalMaterializedCommit,
        obligation_closed: bool,
    ) -> (ContentWriteClose, bool) {
        use yadorilink_sync_sqlite::exact_materialized_commit::InternalMaterializedCommit;
        match commit {
            InternalMaterializedCommit::Published(_) => {}
            InternalMaterializedCommit::FenceLost { live_mutation_generation } => {
                tracing::warn!(
                    group_id,
                    path,
                    expected_mutation_generation,
                    ?live_mutation_generation,
                    "another mutator advanced this path's fence between its write and this \
                     commit; nothing was recorded and the intent and obligation stay open"
                );
                return (ContentWriteClose::Refused, false);
            }
            InternalMaterializedCommit::AuthoringSuperseded => {
                tracing::warn!(
                    group_id,
                    path,
                    "this path was superseded while its write was in flight; the bytes just \
                     written are stale for whatever version is current now, so nothing was \
                     recorded"
                );
                return (ContentWriteClose::Refused, false);
            }
        }
        if !obligation_closed && claim.is_some() {
            tracing::debug!(
                group_id,
                path,
                "the proof landed but the claim on this path's obligation had been overtaken; \
                 the obligation stays open for its next claim"
            );
        }
        (
            ContentWriteClose::Published {
                obligation: claim.map(|_| {
                    if obligation_closed {
                        ObligationDecision::Closed
                    } else {
                        ObligationDecision::LeftOpen
                    }
                }),
            },
            obligation_closed,
        )
    }

    /// [`Self::close_content_write`] for several files in ONE transaction.
    ///
    /// Each item is closed by the same checks and writes as the single-file
    /// close, in its own savepoint (see
    /// `yadorilink_sync_sqlite::exact_materialized_commit::close_content_writes_in_tx`),
    /// with its own claim, fence, authoring guard and root-identity check:
    /// one item's refusal or failure is that item's outcome and leaves the
    /// others committed. The outer result is an error only when the
    /// transaction itself failed, in which case no item was written.
    ///
    /// The caller owns the guards of every item (its path lock, its root
    /// operation, its disk reservation) and holds them until the item's
    /// outcome has been handed back.
    pub(crate) fn close_content_writes(
        &self,
        items: &[&ContentWriteCloseItem],
    ) -> Result<Vec<Result<ContentWriteClose, PeerSessionError>>, PeerSessionError> {
        use yadorilink_sync_sqlite::exact_materialized_commit::{
            close_content_writes_in_tx, CloseWriteRequest, ExpectedAuthoring,
        };
        #[cfg(test)]
        {
            let gate = self
                .test_observers
                .close_batch_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if let Some(gate) = gate {
                gate();
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let requests: Vec<CloseWriteRequest<'_>> = items
            .iter()
            .map(|item| CloseWriteRequest {
                group_id: &item.group_id,
                path: &item.path,
                exact_state: &item.exact_state,
                expected_mutation_generation: item.expected_mutation_generation,
                expected_authoring: ExpectedAuthoring {
                    state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
                    expected_version: Some(&item.expected_version),
                },
                claim: item.claim,
                intent: item.intent,
            })
            .collect();
        let outcomes = self
            .database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                let outcomes = close_content_writes_in_tx(
                    tx,
                    &requests,
                    now,
                    |index| (items[index].disk_check)(),
                    |index| items[index].root_check.verify().map_err(Into::into),
                )?;
                #[cfg(test)]
                {
                    self.test_observers
                        .close_batch_sizes
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(items.len());
                    if self
                        .test_observers
                        .close_batch_fails_before_commit
                        .load(std::sync::atomic::Ordering::SeqCst)
                    {
                        return Err(yadorilink_sync_sqlite::SyncSqliteError::CorruptState(
                            "injected failure before the batch commits".into(),
                        ));
                    }
                }
                Ok(outcomes)
            })
            .map_err(crate::sync_error::SyncError::from)?;
        let mut woken: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut results = Vec::with_capacity(items.len());
        for (item, outcome) in items.iter().zip(outcomes) {
            results.push(match outcome {
                Ok((commit, closed)) => {
                    let (close, closed) = Self::describe_content_write_close(
                        &item.group_id,
                        &item.path,
                        item.expected_mutation_generation,
                        item.claim,
                        commit,
                        closed,
                    );
                    if closed {
                        woken.insert(&item.group_id);
                    }
                    Ok(close)
                }
                Err(error) => {
                    Err(PeerSessionError::from(crate::sync_error::SyncError::from(error)))
                }
            });
        }
        for group_id in woken {
            self.hazard_recheck_wake().mark_dirty(group_id);
        }
        Ok(results)
    }

    /// Clears the write intents of received files whose batch flush is done, in
    /// one transaction: each `(group, path, fence)` only if its intent is still
    /// the one marked as waiting for the flush of the write published under
    /// that fence. Returns how many were cleared.
    pub(crate) fn clear_flush_pending_intents(
        &self,
        flushed: &[(&str, &str, i64)],
    ) -> Result<usize, PeerSessionError> {
        if flushed.is_empty() {
            return Ok(0);
        }
        let cleared = self
            .database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                let mut cleared = 0;
                for (group_id, path, generation) in flushed {
                    if yadorilink_sync_sqlite::clear_flush_pending_in_tx(
                        tx,
                        group_id,
                        path,
                        *generation,
                    )? {
                        cleared += 1;
                    }
                }
                Ok(cleared)
            })
            .map_err(crate::sync_error::SyncError::from)?;
        Ok(cleared)
    }

    /// Open half of recording a version without its content, for the
    /// on-demand lane and for the eager lane's incomplete-content arm: open
    /// the intent (tx), persist the row (tx), clear any hazard hold (tx, no
    /// permit), and set the row to what the path holds (tx): `Present` when
    /// a local object is there (`object_present`: an older version's bytes
    /// stay under the newer row, and nothing here claims they equal it),
    /// `Remote` when the path is empty. The lane then verifies the target and
    /// bumps the fence (`place_provider_object`).
    ///
    /// Not the eager lane's reconstruct-failed demotion: that one enters
    /// from `Hydrating` after a real write attempt, clears no hold, and
    /// stays a single state set in the lane.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_remote_write<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        row_authority: RowAuthority<'_>,
        object_present: bool,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<LaneIntent<'a>, PeerSessionError> {
        let intent_guard = self.open_intent_and_persist_row(
            group_id,
            record,
            origin_device_id,
            authoring,
            meta,
            row_authority,
            permit,
        )?;
        self.clear_held(group_id, &record.path)?;
        self.set_materialization_state(
            group_id,
            &record.path,
            if object_present {
                MaterializationState::Present
            } else {
                MaterializationState::Remote
            },
            permit,
        )?;
        Ok(intent_guard)
    }

    /// Symlink lane, leaving a hazard hold: a held row is `Remote`
    /// with `held_reason` set, and the SET `held_reason` is itself what
    /// protects it from the tombstone loop while held. So when the path was
    /// held (a read), an intent naming `intent_target_hash` is opened (tx)
    /// BEFORE the hold is cleared (tx), and handed back for the lane to
    /// keep, uncleared, until it returns: a `PolicySkipped` or failure exit
    /// then still leaves the row protected. Not opened when the path was
    /// never held, so an unheld retry writes no intent.
    ///
    /// The symlink lane's own step, not a shared release: convergence
    /// rehydration leaves a hold differently.
    pub(crate) fn release_symlink_hold_under_intent<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        intent_target_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Option<LaneIntent<'a>>, PeerSessionError> {
        let was_held = self.get_held_state(group_id, path)?.is_some();
        let pre_clear_hold_intent_guard = if was_held {
            Some(self.open_materialization_intent_guard(
                group_id,
                path,
                intent_target_hash,
                permit,
            )?)
        } else {
            None
        };
        self.clear_held(group_id, path)?;
        Ok(pre_clear_hold_intent_guard)
    }

    /// Open half of a symlink write (`materialize_symlink_at`). When there
    /// is a `write_target` (the caller decided the link will really be
    /// written): bump the fence (tx), then open the intent naming the
    /// target (tx). Then upsert the row (tx) unless this exact authored
    /// version is already current (a read), and, for a real write, mark the
    /// row in flight (tx). Returns the fence value and the intent for a
    /// real write, `None` for a policy skip (which still upserts).
    // One argument per input of the persisted row.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_symlink_write<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        write_target: Option<&[u8]>,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Option<(i64, LaneIntent<'a>)>, PeerSessionError> {
        self.open_single_object_write(
            group_id,
            record,
            origin_device_id,
            authoring,
            meta,
            write_target,
            "symlink_write",
            permit,
        )
    }

    /// Open half of an explicit directory's write (the directory lane):
    /// exactly [`Self::open_symlink_write`]'s steps for an object with no
    /// content -- bump the fence (tx), open the intent (tx), upsert the row
    /// unless this authored version is already current, mark it in flight
    /// (tx). The intent names the empty content, which classifies it as a
    /// write, so repair recreates a directory it finds missing under it.
    pub(crate) fn open_directory_write<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<(i64, LaneIntent<'a>), PeerSessionError> {
        self.open_single_object_write(
            group_id,
            record,
            origin_device_id,
            authoring,
            meta,
            Some(&[]),
            "directory_write",
            permit,
        )?
        .ok_or_else(|| {
            PeerSessionError::CorruptState(format!(
                "{}: a directory write opened no intent",
                record.path
            ))
        })
    }

    /// Settle half of an explicit directory's write: the exact proof for
    /// `version` with the identity observed at `out_path`, the `Present`
    /// stamp and the intent clear, in one transaction guarded on the fence
    /// value the open returned and on the row still being this authored
    /// version in flight. On success the path holds an entry again, so a
    /// retained record for it (a directory kept after an earlier delete)
    /// is released. `false` when the commit was refused: nothing was
    /// written and the intent stays open.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settle_directory_write(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        version: VersionHash,
        mutation_generation: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, PeerSessionError> {
        let identity =
            yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(out_path).ok();
        let committed = self.commit_internal_materialized_state_if_fence_current(
            group_id,
            path,
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind: yadorilink_replica_domain::file::RecordKind::Directory,
                version,
                identity: Box::new(identity),
            },
            mutation_generation,
            Some(yadorilink_peer_session::ports::ExpectedAuthoring {
                state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
                expected_version: Some(&version),
            }),
            permit,
        )?;
        if committed {
            self.release_retained_directory(group_id, path)
                .map_err(crate::sync_error::SyncError::from)?;
        }
        Ok(committed)
    }

    /// The shared open half of a single-object write with no block
    /// content (a symlink, an explicit directory). See
    /// [`Self::open_symlink_write`].
    #[allow(clippy::too_many_arguments)]
    fn open_single_object_write<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        write_target: Option<&[u8]>,
        fence_reason: &'static str,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Option<(i64, LaneIntent<'a>)>, PeerSessionError> {
        let opened = match write_target {
            Some(target) => {
                let mutation_generation =
                    self.dag_bump_mutation_fence(group_id, &record.path, fence_reason)?;
                let target_hash = yadorilink_local_storage::intent_target_hash_for_bytes(target);
                let intent_guard = self.open_materialization_intent_guard(
                    group_id,
                    &record.path,
                    &target_hash,
                    permit,
                )?;
                Some((mutation_generation, intent_guard))
            }
            None => None,
        };

        // A permanently policy-skipped symlink (no target recorded, or a
        // Windows peer that has not opted in) retries this whole write on a
        // capped backoff that is never dead-lettered -- every retry used to
        // unconditionally re-upsert `record` even when nothing had changed
        // since the previous attempt. `upsert_file_in_tx`'s own `INSERT` is
        // unconditional too: it flips the current row to `superseded`/
        // `trashed` and inserts a fresh `version_seq` row every single call,
        // so a long-lived policy skip accumulated an unbounded number of
        // these no-op version rows over the process's lifetime -- purely
        // from retrying, with the actual desired state never once changing.
        // Skip the upsert when this exact authored version is already the
        // current one; whether this is a real write is unaffected either
        // way.
        // `is_some_and` means a `None` authoring identity always yields
        // `false` here -- a caller with no head to compare against
        // gets no dedup at all, and still accumulates a version row on every
        // retry exactly as before this fix. At least one caller does pass
        // `None` (the tombstone-materialize call in the deletion path) --
        // not confirmed reachable for a retry-prone policy-skipped SYMLINK
        // specifically (a tombstone is `record.deleted`, a different
        // dispatch branch), but not proven unreachable either.
        let already_current = authoring.is_some_and(|identity| {
            self.row_authoring(group_id, &record.path).ok().flatten().as_ref() == Some(identity)
        });
        if !already_current {
            self.upsert_file_with_origin_and_authoring(
                group_id,
                record,
                origin_device_id,
                authoring,
                Some(meta),
                permit,
            )?;
        }

        // The row this write targets is established; mark it as a
        // materialization in flight before the syscall, and leave the exact
        // claim to the commit that can prove it. `upsert_file_with_origin`
        // above carries the previous version's `materialization_state`
        // forward, so an existing `Present` symlink would otherwise still
        // read `Present` here -- with its old proof already dead, because
        // the fence was bumped above, and the new one not yet published.
        // Same discipline the projected-upserts batch uses, for the same
        // window.
        if opened.is_some() {
            self.set_materialization_state(
                group_id,
                &record.path,
                yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
                permit,
            )?;
        }
        Ok(opened)
    }

    /// The hazard hold (`hold_record`): adopt `record` into the index with
    /// its origin and author (tx), set the row `Remote` (tx),
    /// and mark it held with `reason` (tx, no permit). Three transactions,
    /// in that order; nothing is written on disk under any name.
    ///
    /// Not the tombstone lane's or rehydration's hold, which set the held
    /// marker without touching the row.
    #[allow(clippy::too_many_arguments)] // one argument per input of the held row
    pub(crate) fn hold_row_for_hazard(
        &self,
        group_id: &str,
        record: &FileRecord,
        reason: &str,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        // The row is written with the version's own metadata columns: a row
        // that cites a native head must show the version that head carries,
        // and a version's mode and xattrs are part of its identity.
        self.apply_projected_row_atomic(
            group_id,
            record,
            origin_device_id,
            authoring,
            meta,
            permit,
        )?;
        // A held row is, by definition, "not materialized under any name on
        // this device" -- the upsert above leaves `materialization_state` at
        // its schema default of `Present`, which is wrong the instant the
        // row becomes held, not just eventually. Left at `Present`, the
        // periodic repair sweep reads this row (nothing on disk, no
        // materialization intent) as an offline deletion and journals it
        // dirty; the always-running dirty-journal redrive then emits a real,
        // propagating tombstone Change for a path this device never actually
        // deleted. This is reachable on every platform (unlike the
        // Windows-symlink-policy case): a brand-new hazard hold hits it
        // immediately, with no materialize/PolicySkipped round trip needed
        // first. Matches `hydration::hydrate_inner`'s own
        // hazard-hold outcome, which reverts to `Remote` for the
        // identical reason.
        self.set_materialization_state(
            group_id,
            &record.path,
            MaterializationState::Remote,
            permit,
        )?;
        self.set_held(
            group_id,
            &record.path,
            reason,
            crate::local_convergence::types::now_unix_nanos(),
        )?;
        Ok(())
    }

    /// Single-path tombstone on a hazardous live row: mark the row held
    /// with `reason` (tx, no permit) only when it is not already held for
    /// that same reason (a read), so a hold re-confirmed on every retry
    /// keeps the time it first applied. The row itself is not touched.
    pub(crate) fn rehold_if_reason_changed(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
    ) -> Result<(), PeerSessionError> {
        let already_held =
            self.get_held_state(group_id, path)?.is_some_and(|held| held.reason == *reason);
        if !already_held {
            self.set_held(
                group_id,
                path,
                reason,
                crate::local_convergence::types::now_unix_nanos(),
            )?;
        }
        Ok(())
    }

    /// Holds `path`, whose existing file at `out_path` denies its owner read
    /// access, instead of applying `version`'s replicated metadata to it
    /// (tx, no permit). Nothing on disk is touched and the fence is only
    /// read. Records what the decision was made against
    /// ([`Self::metadata_unprovable_key`]) so the hazard re-check can skip
    /// the path until that changes, and keeps the time of the first hold
    /// for this reason. Returns the held reason, for the lane's
    /// `HazardHeld` settlement.
    pub(crate) fn hold_metadata_unprovable(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        version: &VersionHash,
    ) -> Result<String, PeerSessionError> {
        #[cfg(test)]
        self.test_observers.note_metadata_unprovable_hold();
        let reason = yadorilink_peer_session::hazard::metadata_unprovable_reason();
        let key = self.metadata_unprovable_key(group_id, path, out_path, version)?;
        let since = match self.get_held_state(group_id, path)? {
            Some(held) if held.reason == reason => held.since_unix_nanos,
            _ => crate::local_convergence::types::now_unix_nanos(),
        };
        self.materialization_state_repository()
            .set_held_with_key(group_id, path, &reason, since, key.as_deref())
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)?;
        tracing::warn!(
            group_id,
            path,
            "holding a path whose existing file is not readable by its owner: its replicated \
             metadata cannot be confirmed or applied, and its content is left as it is"
        );
        Ok(reason)
    }

    /// Whether `path` is held as metadata-unprovable and nothing it was
    /// held against has changed since: the same file (identity, and a
    /// metadata fingerprint that covers mode, size, mtime and ctime), the
    /// same mutation fence, and the same desired `version`. A re-check of
    /// such a path would only repeat the decision. Anything unreadable or
    /// unobservable answers `false`, so the path is looked at again.
    pub(crate) fn metadata_unprovable_hold_unchanged(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        version: &VersionHash,
    ) -> Result<bool, PeerSessionError> {
        let held_for_metadata = self.get_held_state(group_id, path)?.is_some_and(|held| {
            held.reason
                .starts_with(yadorilink_peer_session::hazard::HELD_REASON_METADATA_UNPROVABLE)
        });
        if !held_for_metadata {
            return Ok(false);
        }
        let Some(stored) = self
            .materialization_state_repository()
            .get_held_key(group_id, path)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)?
        else {
            return Ok(false);
        };
        Ok(self.metadata_unprovable_key(group_id, path, out_path, version)?.as_deref()
            == Some(stored.as_str()))
    }

    /// Lifts a metadata-unprovable hold once the path has settled; a hold
    /// for any other reason is left for its own lane to lift.
    pub(crate) fn clear_metadata_unprovable_hold(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), PeerSessionError> {
        let held_for_metadata = self.get_held_state(group_id, path)?.is_some_and(|held| {
            held.reason
                .starts_with(yadorilink_peer_session::hazard::HELD_REASON_METADATA_UNPROVABLE)
        });
        if held_for_metadata {
            self.clear_held(group_id, path)?;
        }
        Ok(())
    }

    /// What a metadata-unprovable hold is decided against: the desired
    /// version, the path's current mutation fence, and the observed
    /// identity of the file (an `lstat`, no read access needed). A user's
    /// `chmod` or edit changes the fingerprint (it covers mode and ctime),
    /// any daemon write bumps the fence, and a new version changes the
    /// hash. `None` when the file cannot be observed.
    fn metadata_unprovable_key(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        version: &VersionHash,
    ) -> Result<Option<String>, PeerSessionError> {
        let Ok(identity) =
            yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(out_path)
        else {
            return Ok(None);
        };
        let fence = self.dag_snapshot_mutation_fence(group_id, path)?;
        Ok(Some(format!(
            "v1 version={} fence={fence} volume={:?} object={:?} generation={:?} metadata={}",
            version.to_hex(),
            identity.volume_identity,
            identity.object_id,
            identity.generation_or_usn,
            hex::encode(identity.metadata_fingerprint),
        )))
    }

    /// Open half of a single-path tombstone delete: open the intent with
    /// the delete marker as its target (tx), then bump the fence (tx).
    /// Returns the intent the lane holds across the removal, and the fence
    /// value the removal's evidence names. The lane verifies the delete
    /// target before this and removes the file after it.
    pub(crate) fn open_tombstone_delete<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<(LaneIntent<'a>, i64), PeerSessionError> {
        let delete_intent_guard = self.open_materialization_intent_guard(
            group_id,
            path,
            TOMBSTONE_DELETE_INTENT_TARGET,
            permit,
        )?;
        let mutation_generation =
            self.dag_bump_mutation_fence(group_id, path, "tombstone_delete")?;
        Ok((delete_intent_guard, mutation_generation))
    }

    /// What the intent open on `path` is for, if one is open: a delete when
    /// it names the tombstone delete's marker, a write of content
    /// otherwise. Repair decides a missing file by this, never by the raw
    /// target.
    pub(crate) fn materialization_intent_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationIntentKind>, yadorilink_sync_sqlite::SyncSqliteError> {
        Ok(self
            .materialization_intent_repository()
            .materialization_intent_target(group_id, path)?
            .map(|target| {
                if target == TOMBSTONE_DELETE_INTENT_TARGET {
                    MaterializationIntentKind::Delete
                } else {
                    MaterializationIntentKind::Materialize
                }
            }))
    }

    /// Settle half of a tombstone a native delta authored, after the lane's
    /// removal: clear any hold (tx, no permit), persist the tombstone row
    /// under a fresh root operation (tx), then clear the intent (tx).
    ///
    /// A held file that is later tombstoned must not leave an orphaned held
    /// entry once its index row no longer represents a live, on-disk file;
    /// `clear_held` is a safe no-op when the path was never held. The
    /// intent is cleared only after the index durably reflects the
    /// deletion. An early error drops it uncleared instead, which is the
    /// fail-safe outcome: the next pass treats the path as still
    /// mid-operation, never as a fresh offline deletion. The fresh root
    /// operation is begun only here, after the hold clear, so a link that
    /// stopped meanwhile refuses the row and leaves the intent open.
    pub(crate) fn settle_tombstone_delete(
        &self,
        delete_intent_guard: LaneIntent<'_>,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        row_authority: RowAuthority<'_>,
    ) -> Result<(), PeerSessionError> {
        self.clear_held(group_id, &record.path)?;
        self.persist_row_under_fresh_operation(
            group_id,
            record,
            origin_device_id,
            authoring,
            None,
            row_authority,
        )?;
        delete_intent_guard.clear()
    }

    /// Settle half of a displacement's delete (a tombstone no native delta
    /// authors), after the lane's removal: clear any hold (tx, no permit),
    /// erase the local-only row under the caller's permit (tx), then clear
    /// the intent (tx). Kept apart from [`Self::settle_tombstone_delete`]:
    /// this is not a fresh mutation, and it asserts no tombstone fact.
    pub(crate) fn settle_retired_copy_erase(
        &self,
        delete_intent_guard: LaneIntent<'_>,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.clear_held(group_id, path)?;
        self.erase_local_only_file(group_id, path, permit)?;
        delete_intent_guard.clear()
    }

    /// The engine's completion of a claimed obligation against exact
    /// evidence (after its publication, or for a zero-work close): derive
    /// the desired resolved-path-state hash from `exact_state`, then close
    /// the obligation in one transaction only if its claimed generation and
    /// incarnation still hold and a current proof matches that hash.
    /// Never publishes; the engine's publication stays its own transaction.
    pub(crate) fn complete_obligation_exact(
        &self,
        group_id: &str,
        path: &str,
        claimed_generation: i64,
        claimed_incarnation: i64,
        exact_state: &yadorilink_peer_session::ports::ExactActualState,
    ) -> Result<bool, yadorilink_sync_sqlite::SyncSqliteError> {
        let desired_hash = exact_state_desired_hash(group_id, path, exact_state);
        self.sqlite().dag_complete_obligation_if_exact_proof_current(
            group_id,
            path,
            claimed_generation,
            claimed_incarnation,
            &desired_hash,
        )
    }

    /// The engine's zero-work close: the same exact-evidence completion as
    /// [`Self::complete_obligation_exact`], which additionally re-anchors
    /// the proof it closes against on the current frontier, in the same
    /// transaction. Nothing was written to disk, so no real publication
    /// refreshed the proof's causal basis -- and that basis is what the
    /// next local edit of the path is parented on. See
    /// `complete_zero_work_obligation_rebasing_proof`.
    pub(crate) fn complete_zero_work_obligation(
        &self,
        group_id: &str,
        path: &str,
        claimed_generation: i64,
        claimed_incarnation: i64,
        exact_state: &yadorilink_peer_session::ports::ExactActualState,
    ) -> Result<bool, yadorilink_sync_sqlite::SyncSqliteError> {
        let desired_hash = exact_state_desired_hash(group_id, path, exact_state);
        self.sqlite().dag_complete_zero_work_obligation_rebasing_proof(
            group_id,
            path,
            claimed_generation,
            claimed_incarnation,
            &desired_hash,
        )
    }

    /// The engine's completion of a claimed obligation against non-exact
    /// evidence (a policy placeholder, a hazard hold, an ignore exclusion):
    /// one transaction, closing only if the claimed generation and
    /// incarnation still hold. Nothing is published.
    pub(crate) fn complete_obligation_non_exact(
        &self,
        group_id: &str,
        path: &str,
        claimed_generation: i64,
        claimed_incarnation: i64,
        proof: yadorilink_sync_sqlite::projection_obligations::NonExactProofKind,
    ) -> Result<bool, yadorilink_sync_sqlite::SyncSqliteError> {
        self.sqlite().dag_complete_obligation_if_non_exact_proof_current(
            group_id,
            path,
            claimed_generation,
            claimed_incarnation,
            proof,
        )
    }
}

/// The resolved-path-state hash an exact completion closes against,
/// derived from the exact state the caller verified.
fn exact_state_desired_hash(
    group_id: &str,
    path: &str,
    exact_state: &yadorilink_peer_session::ports::ExactActualState,
) -> [u8; 32] {
    use yadorilink_peer_session::ports::ExactActualState;
    use yadorilink_sync_sqlite::materialized_generation::{
        compute_resolved_path_state_hash, MaterializedObjectKind,
    };
    let (object_kind, version) = match exact_state {
        ExactActualState::Object { kind, version, .. } => {
            (completion_object_kind(*kind), Some(*version))
        }
        ExactActualState::Absent => (MaterializedObjectKind::Absent, None),
        ExactActualState::StructuralDirectory { .. } => {
            (MaterializedObjectKind::StructuralDirectory, None)
        }
    };
    compute_resolved_path_state_hash(group_id, path, object_kind, version.as_ref())
}

/// `RecordKind` -> `MaterializedObjectKind`, for computing the desired-side
/// hash a freshly published exact evidence must be closed against. The same
/// correspondence is implemented inline in `peer_replica_state`'s publish
/// impl (which maps the identical `ExactActualState::Object.kind` to build
/// the write it sends to `path_materialized_generations`); kept as a
/// trivial three-arm match rather than a shared export.
fn completion_object_kind(
    kind: yadorilink_replica_domain::file::RecordKind,
) -> yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind {
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind;
    match kind {
        RecordKind::File => MaterializedObjectKind::RegularFile,
        RecordKind::Directory => MaterializedObjectKind::Directory,
        RecordKind::Symlink => MaterializedObjectKind::Symlink,
    }
}

/// The columns of a plain regular file, for tests that open a write without
/// caring what the version's metadata is.
#[cfg(test)]
pub(crate) fn plain_file_columns() -> yadorilink_replica_domain::session_state::LocalFileMetaColumns
{
    yadorilink_replica_domain::session_state::LocalFileMetaColumns {
        record_kind: yadorilink_replica_domain::file::RecordKind::File,
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode: None,
        xattrs: Vec::new(),
    }
}

/// One file's open, owned, so it can run on the blocking pool: the statements
/// of [`ReplicaCoordinator::open_content_write`] and the two root checks that
/// end its transaction (the lane's permit and the row's fresh one).
pub(crate) struct OwnedContentWriteOpen {
    pub(crate) group_id: String,
    pub(crate) record: FileRecord,
    pub(crate) origin_device_id: String,
    pub(crate) authoring: Option<yadorilink_replica_domain::native_plan::NativeRowIdentity>,
    pub(crate) meta: yadorilink_replica_domain::session_state::LocalFileMetaColumns,
    pub(crate) intent_target_hash: Vec<u8>,
    pub(crate) now: i64,
    pub(crate) lane_check: yadorilink_root_authority::root_commit::OwnedPermitCheck,
    pub(crate) row_check: yadorilink_root_authority::root_commit::OwnedPermitCheck,
    /// Runs first inside the transaction, once (the writer retries a
    /// transaction that hit a transient lock).
    #[cfg(test)]
    pub(crate) gate: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    pub(crate) gate_fired: std::sync::atomic::AtomicBool,
}

impl OwnedContentWriteOpen {
    /// The statements' inputs, borrowed.
    pub(crate) fn request(
        &self,
    ) -> yadorilink_sync_sqlite::content_write_open::OpenWriteRequest<'_> {
        yadorilink_sync_sqlite::content_write_open::OpenWriteRequest {
            group_id: &self.group_id,
            record: &self.record,
            origin_device_id: &self.origin_device_id,
            authoring: self.authoring.as_ref(),
            meta: &self.meta,
            intent_target_hash: &self.intent_target_hash,
            in_flight_state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
            now_unix_nanos: self.now,
        }
    }

    /// The lane's permit check, then the row's fresh one, as the single-file
    /// open runs them right before it commits.
    pub(crate) fn verify_roots(&self) -> Result<(), yadorilink_sync_sqlite::SyncSqliteError> {
        self.lane_check.verify()?;
        self.row_check.verify()?;
        Ok(())
    }

    /// The statements, then both root checks, inside the caller's transaction.
    pub(crate) fn run_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<i64, yadorilink_sync_sqlite::SyncSqliteError> {
        #[cfg(test)]
        if let Some(gate) = &self.gate {
            if !self.gate_fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                gate();
            }
        }
        let fence = yadorilink_sync_sqlite::content_write_open::open_content_write_in_tx(
            tx,
            &self.request(),
        )?;
        self.verify_roots()?;
        Ok(fence)
    }
}

/// One file's close, owned, so it can wait in a window's queue while the
/// file's task keeps its guards: see [`ReplicaCoordinator::close_content_writes`].
pub(crate) struct ContentWriteCloseItem {
    pub(crate) group_id: String,
    pub(crate) path: String,
    pub(crate) exact_state:
        yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState,
    pub(crate) expected_mutation_generation: i64,
    /// The version the row must still name, with the row in flight.
    pub(crate) expected_version: VersionHash,
    pub(crate) claim: Option<yadorilink_sync_sqlite::projection_obligations::ObligationClaimToken>,
    /// The file's own root permit, as the check the single-file close runs
    /// inside its transaction.
    pub(crate) root_check: yadorilink_root_authority::root_commit::OwnedPermitCheck,
    /// Whether the file on disk is still exactly what the item was verified
    /// as, checked inside the batch transaction right before this item's close
    /// statements: the file may have waited for its batch, and a direct write
    /// by the user does not move the fence.
    pub(crate) disk_check: Box<dyn Fn() -> bool + Send + Sync>,
    /// What the close does with the write intent: cleared, unless the file's
    /// flush is owed to a batch barrier.
    pub(crate) intent: yadorilink_sync_sqlite::IntentDisposition,
}

/// What [`ReplicaCoordinator::close_content_write`] committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentWriteClose {
    /// Nothing at all: the fence had moved or the row was superseded. The
    /// intent and the obligation are still open.
    Refused,
    /// The proof, the `Present` stamp and the intent clear landed. With a
    /// claim, `obligation` says what the same commit did with it; without
    /// one it is `None` and the obligation was not touched.
    Published { obligation: Option<ObligationDecision> },
}

/// What the commit that published a proof did with the claimed obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObligationDecision {
    Closed,
    /// The claim was stale: a newer admission or a re-arm moved the
    /// obligation, which stays open for its next claim.
    LeftOpen,
}
