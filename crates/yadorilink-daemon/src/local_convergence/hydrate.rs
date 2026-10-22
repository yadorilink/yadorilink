use futures_util::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::LinkGate;
use yadorilink_replica_domain::session_state::MaterializationPolicy;

use super::types::*;
use yadorilink_peer_session::peer_session::*;

impl super::LocalConvergenceExecutor {
    pub async fn reconcile_paths_directly(
        self: &Arc<Self>,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        paths: std::collections::BTreeSet<String>,
    ) -> Result<Option<ProjectionAttempt>, yadorilink_peer_session::PeerSessionError> {
        // ONE timer for the whole attempt -- see the inner function's own
        // comment for why it cannot be created further down.
        let call_timer = crate::local_convergence::call_timer::ReconcileCallTimer::new();
        self.reconcile_paths_directly_with_timer(driver, group_id, paths, None, &call_timer).await
    }

    /// [`Self::reconcile_paths_directly`] for paths the obligation engine
    /// holds claims on. A lane that can close a claimed path's obligation in
    /// the same transaction as its proof does so, and records it in
    /// `claims` so the engine does not complete it a second time.
    pub(crate) async fn reconcile_claimed_paths(
        self: &Arc<Self>,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        paths: std::collections::BTreeSet<String>,
        claims: &super::obligation_claims::ObligationClaims,
    ) -> Result<Option<ProjectionAttempt>, yadorilink_peer_session::PeerSessionError> {
        let call_timer = crate::local_convergence::call_timer::ReconcileCallTimer::new();
        self.reconcile_paths_directly_with_timer(driver, group_id, paths, Some(claims), &call_timer)
            .await
    }

    pub(crate) async fn reconcile_paths_directly_with_timer(
        self: &Arc<Self>,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        paths: std::collections::BTreeSet<String>,
        claims: Option<&super::obligation_claims::ObligationClaims>,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<Option<ProjectionAttempt>, yadorilink_peer_session::PeerSessionError> {
        let audit_attempt_id = next_audit_attempt_id();
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            audit_attempt_id,
            path_count = paths.len(),
            paths = ?paths,
            "direct path reconciliation attempt starting"
        );
        // Obtain what this pass will need, once, before it runs.
        //
        // The pass itself is local: it decides everything from this device's
        // disk, index and native state, and it is entered from the top with the content
        // already here rather than being suspended in the middle of a decision
        // while a peer answers. Which peer, how many blocks at once, what a
        // `DontHave` means and what to do with a transport error are all
        // settled here, on the side that has a peer.
        //
        // A plan that goes stale between the request and the pass costs a
        // wasted fetch and nothing else: the pass re-resolves every path
        // itself, and what it observed before the request is carried in so the
        // guard against a local editor writing during the fetch still has its
        // before-picture.
        // `call_timer` spans BOTH halves below and is owned by the caller,
        // because the block fetching this attempt does happens in
        // `obtain_missing_content` -- strictly before `reconcile_group_
        // paths` is entered. A timer created down there cannot observe any
        // of it, so every block-fetch counter the reported line carries
        // (`blocks_fetched`, `block_fetch_wait_ms`) was structurally pinned
        // at zero on this path regardless of what actually happened on the
        // wire: measured against a real two-device run, 13,340 genuine
        // block round trips all reported as `blocks_fetched=0
        // block_fetch_wait_ms=0`. Threading one timer through both halves
        // is what makes the reported line describe the whole attempt --
        // the "constructed once per call and threaded by reference through
        // every function that call touches" property this module's own doc
        // comment already claims.
        // Deferred before fetching or planning anything for a group still starting up.
        if !self.startup_admits_peer_apply(group_id) {
            return Ok(None);
        }
        let window = crate::receive_diag::window_begin(group_id);
        let path_count = paths.len();
        let fetch_started = crate::receive_diag::clock();
        let prefetched = self.obtain_missing_content(driver, group_id, &paths, call_timer).await?;
        if let Some(started) = fetch_started {
            call_timer.add_window_fetch(started.elapsed());
        }
        let attempt = self
            .reconcile_group_paths_guarded(
                group_id,
                paths,
                driver.peer_device_id(),
                &prefetched,
                claims,
                audit_attempt_id,
                call_timer,
            )
            .await;
        if let (Some(window), Ok(Some(_))) = (window, &attempt) {
            crate::receive_diag::window_end(
                group_id,
                window,
                path_count,
                call_timer.window_phases(),
            );
        }
        attempt
    }

    /// Applies one committed batch. Only here does a hash become
    /// provenance-eligible, which is what keeps "provenance is recorded
    /// strictly after the durable write it attests to" true under batching.
    fn absorb_commit_result(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        joined: Result<CommittedBatch, tokio::task::JoinError>,
        pool: &mut ReceiveCommitPool,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) {
        let committed = match joined {
            Ok(committed) => committed,
            Err(join_err) => {
                if pool.fatal.is_none() {
                    pool.fatal = Some(PeerSessionError::from(std::io::Error::other(format!(
                        "block store write task panicked: {join_err}"
                    ))));
                }
                pool.lost_content = true;
                return;
            }
        };
        if let (Some(timer), Some(elapsed)) = (call_timer, committed.elapsed) {
            timer.add_store_put(elapsed);
        }
        for rejected in &committed.rejected {
            tracing::warn!(
                local_device_id = %self.local_device_id,
                candidate_peer_id = %driver.peer_device_id(),
                hash = %hex::encode(rejected),
                "peer returned bytes that do not hash to the requested block; discarding them"
            );
            pool.lost_content = true;
        }
        if let Some(e) = committed.error {
            if pool.fatal.is_none() {
                pool.fatal = Some(e.into());
            }
            // The batch is all-or-nothing, so nothing in it is durable and
            // nothing in it may be provenanced.
            pool.lost_content = true;
            return;
        }
        for hash in committed.hashes {
            if let Some(batch) = &pool.reconcile_batch {
                batch.record(hash.clone());
            }
            pool.durable.push(hash);
        }
    }

    /// Routes one completed fetch into the pool, or into the
    /// give-up/fatal state. Deliberately does NOT touch `pool.durable`: a
    /// fetched block is not yet a durable one, and that field is what
    /// provenance is drawn from.
    ///
    /// Takes the per-file loop state as explicit `&mut` arguments rather
    /// than a wrapper struct: each is genuinely per-invocation state the
    /// two call sites (mid-loop drain and final drain) share, and a struct
    /// whose only purpose is to satisfy an argument count would obscure
    /// that they are separate concerns.
    #[allow(clippy::too_many_arguments)]
    async fn absorb_fetch_result(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        result: Result<yadorilink_peer_session::convergence_driver::FetchedBlock, PeerSessionError>,
        pool: &mut ReceiveCommitPool,
        group_id: &str,
        file_path: &str,
        version_hex: &str,
        all_present: &mut bool,
        give_up: &mut bool,
        fatal_error: &mut Option<PeerSessionError>,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) {
        let result = result.map(|fetched| {
            // The session reports the wire wait; attributing it is this
            // side's business, which is exactly why it is a `Duration` at
            // the boundary and not a timer the session writes into.
            if let Some(timer) = call_timer {
                timer.add_block_fetch_wait(fetched.wire_wait);
            }
            fetched.outcome
        });
        match result {
            Ok(yadorilink_peer_session::convergence_driver::BlockFetch::Fetched { hash, data }) => {
                if let Some(timer) = call_timer {
                    timer.add_block_fetched();
                }
                self.pool_push(
                    driver,
                    pool,
                    PendingBlock {
                        hash,
                        data,
                        path: file_path.to_string(),
                        version_hex: version_hex.to_string(),
                    },
                    call_timer,
                )
                .await;
            }
            Ok(yadorilink_peer_session::convergence_driver::BlockFetch::Missing) => {
                *all_present = false;
                *give_up = true;
            }
            Ok(yadorilink_peer_session::convergence_driver::BlockFetch::VerifiedRefusal {
                reason,
            }) => {
                self.record_refusal(driver, group_id, file_path, version_hex, &reason);
                *all_present = false;
                *give_up = true;
            }
            Err(e) => {
                if fatal_error.is_none() {
                    *fatal_error = Some(e);
                }
                *give_up = true;
            }
        }
    }

    /// The one fetch answer worth keeping. Written here because this is the
    /// side that owns this device's durable state -- the session reports
    /// what the peer said and does not record it. Bound to the exact
    /// version asked for, so a later version of the same path is not held
    /// back by an older one's refusal (see `block_fetch_refusals`'s schema
    /// doc). Best-effort: losing the evidence must not fail the fetch, which
    /// failed on its own terms anyway.
    fn record_refusal(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        file_path: &str,
        version_hex: &str,
        reason: &str,
    ) {
        if let Err(e) = self.state.record_block_fetch_refusal(
            group_id,
            file_path,
            version_hex,
            driver.peer_device_id(),
            reason,
            crate::local_convergence::types::now_unix_nanos(),
        ) {
            tracing::warn!(
                candidate_peer_id = %driver.peer_device_id(),
                file_path,
                error = %e,
                "failed to record a block fetch refusal"
            );
        }
    }

    /// Fetches only the blocks not already held locally (
    /// missing-block computation; local dedup — a block already
    /// present, from any file/version, is never re-requested). Returns
    /// whether every block ended up present locally — `false` if this
    /// peer reported any as not found, which `hydration::hydrate` uses to know a
    /// fetch is incomplete, not just to log it.
    ///
    /// Retries a bounded number of
    /// times (`NOT_FOUND_RETRY_ATTEMPTS`) before accepting a
    /// `FetchOutcome::NotFound` as final — see `FetchOutcome`'s own doc
    /// comment for why this specifically retries `NotFound` and not
    /// `Unusable` (a decompression failure or similar). Two devices
    /// independently resolving the same conflict compute the same
    /// deterministic conflict-copy path (`conflict::resolve_conflict_names`)
    /// and can each request the other's content for it directly — one
    /// side's request can legitimately arrive before the other side's own
    /// `resolve_and_apply_conflict` has finished materializing/upserting
    /// that exact record locally, so `block_request_is_referenced` finds
    /// nothing yet and refuses with `not_found`. That's a transient race
    /// at the file-record/index layer, not a real content absence — the
    /// requested block's bytes are typically already sitting in the
    /// responding peer's own block store the whole time (it's that
    /// device's own prior edit); what's missing is the index entry
    /// linking the new conflict-copy path to those bytes. Since this
    /// retry is bounded (not indefinite), a block genuinely absent from
    /// every peer still fails — just after a few hundred milliseconds of
    /// retries instead of on the first attempt — so
    /// `a_block_missing_from_every_peer_fails_hydration_cleanly` is
    /// unaffected in outcome, only in exact timing. This intentionally
    /// does NOT retry inside `fetch_block`/`fetch_block_raw` itself: the
    /// *other* caller of `fetch_block` (`yadorilink-daemon`'s multi-peer
    /// hydration dispatcher, `hydration.rs`) already has its own, faster
    /// "this peer doesn't have it — reassign to a different candidate
    /// peer" strategy for the exact same signal, and stacking a same-peer
    /// retry underneath that would only slow down an already-correct
    /// fallback.
    /// Immediate-flush form, unchanged for every caller outside the
    /// ordinary-reconciliation preparation path (`materialize_dag_content_
    /// head`/`materialize`, hydration, etc.): fetches this file's blocks
    /// and flushes their provenance in ONE batched `record_group_block_
    /// provenance` call scoped to this file alone, exactly as before
    /// cross-file batching existed. See `ensure_blocks_present_collecting`
    /// for the reconciliation-only form that defers this flush so several
    /// files can share one transaction.
    pub(crate) async fn ensure_blocks_present(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        file_path: &str,
        record: &FileRecord,
        // The version `record` is, from the caller's payload -- see
        // `ensure_blocks_present_core`.
        version_hash: &VersionHash,
        block_response_timeout: std::time::Duration,
    ) -> Result<bool, PeerSessionError> {
        // A pool of its own, drained before returning: this caller is
        // about one file, so there is no sibling file to share a barrier
        // with and nothing to gain from deferring. Its `all_present` keeps
        // exactly the meaning it always had -- every block durable -- which
        // is why the drain happens here rather than being left to a caller
        // that has no pool.
        let mut pool = ReceiveCommitPool::new(group_id, None);
        let core_result = self
            .ensure_blocks_present_core(
                driver,
                group_id,
                file_path,
                record,
                version_hash,
                block_response_timeout,
                None,
                None,
                &mut pool,
            )
            .await;
        self.pool_drain(driver, &mut pool, None).await;
        let hashes = std::mem::take(&mut pool.durable);
        let flush_result = self.flush_provenance_hashes(group_id, hashes, None).await;
        match core_result.and_then(|all_present| match pool.fatal.take() {
            // A commit that failed after every fetch succeeded is still
            // this call's failure: the blocks are not held.
            Some(e) => Err(e),
            None => Ok(all_present && !pool.lost_content),
        }) {
            // The fetch/store outcome (or its own fatal error) takes
            // precedence over a flush failure, matching this fn's
            // original (pre-split) first-error-wins behavior -- the flush
            // is still attempted either way so a fetch error never
            // discards already-durable siblings' provenance.
            Err(e) => Err(e),
            Ok(all_present) => flush_result.map(|()| all_present),
        }
    }

    /// Cross-file provenance batching: identical fetch/store behavior
    /// to `ensure_blocks_present`, but for the ordinary-reconciliation
    /// preparation path ONLY (`prepare_ordinary_projected_upsert`). Newly-
    /// fetched hashes are NOT flushed here -- returned to the caller
    /// instead, which attaches them to this candidate's own `Prepared
    /// ProjectedUpsert` so `try_commit_ordinary_batch` can flush every
    /// contributing file's hashes (deduplicated) in ONE `record_group_
    /// block_provenance` call per bounded (`ORDINARY_BATCH_MAX_PATHS`)
    /// commit chunk, instead of one call per file.
    ///
    /// The deferral applies ONLY when this call itself succeeds
    /// (`all_present`): a candidate that does NOT reach the batched commit
    /// path (some block missing, or a fatal fetch/store error) flushes its
    /// own partial progress immediately here, exactly like `ensure_blocks_
    /// present` would -- see requirement 6's own reasoning: a hash this
    /// call already durably `store.put` must never be left stranded
    /// unflushed just because ITS OWN candidate never reaches a commit
    /// batch.
    ///
    /// `reconcile_batch` is consulted (in addition to the DB-confirmed
    /// provenance set) so a LATER file in the same bounded reconciliation
    /// window that references a block an EARLIER file already fetched
    /// this same window never re-fetches it merely because that earlier
    /// file's own flush (deferred to the batch boundary) hasn't committed
    /// yet -- see `ReconcileProvenanceBatch`'s own doc comment.
    ///
    /// Only the one-path-at-a-time reference stage still drives this; the
    /// overlapped stage fetches across paths itself.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    async fn ensure_blocks_present_collecting(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        file_path: &str,
        record: &FileRecord,
        version_hash: &VersionHash,
        block_response_timeout: std::time::Duration,
        reconcile_batch: &ReconcileProvenanceBatch,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
        pool: &mut ReceiveCommitPool,
    ) -> Result<bool, PeerSessionError> {
        // No drain, and no per-file provenance flush. Both belong to the
        // pass that owns `pool`: draining here would put a barrier between
        // every pair of files, which for a one-block-per-file workload is
        // the barrier-per-block behaviour this pooling exists to remove.
        //
        // The hashes this file contributed are not returned either --
        // `pool.durable` accumulates every committed hash for the whole
        // pass, and the pass flushes provenance once from it. The previous
        // per-file split (return hashes when the file fully arrived, flush
        // them immediately when it did not) had the same net effect as
        // that single flush, just spread over one transaction per file.
        self.ensure_blocks_present_core(
            driver,
            group_id,
            file_path,
            record,
            version_hash,
            block_response_timeout,
            Some(reconcile_batch),
            Some(call_timer),
            pool,
        )
        .await
    }

    /// Shared fetch/store body for `ensure_blocks_present`/`ensure_blocks_
    /// present_collecting`: always returns every hash this call newly
    /// fetched and durably `store.put`, alongside the fetch/store outcome
    /// (or its own fatal error) -- NEVER flushes provenance itself, that
    /// is entirely the two callers' own responsibility, which is exactly
    /// what lets one defer it and the other not.
    #[allow(clippy::too_many_arguments)]
    async fn ensure_blocks_present_core(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        file_path: &str,
        record: &FileRecord,
        // The version `record` is, from the caller's payload. NOT
        // recomputed from the index row here: `block_fetch_refusals`
        // evidence is bound to the exact version it is about, and a
        // refusal recorded against a hash stitched out of this record
        // plus four live row reads names a version no incarnation of the
        // row ever had -- so it matches nothing later and the refusal is
        // simply lost. The caller holding `path_lock` was the old
        // justification for the stitching, and it is the same one
        // `repair_row_snapshot` rejects: native admission supersedes rows
        // without taking it.
        version_hash: &VersionHash,
        block_response_timeout: std::time::Duration,
        reconcile_batch: Option<&ReconcileProvenanceBatch>,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
        pool: &mut ReceiveCommitPool,
    ) -> Result<bool, PeerSessionError> {
        let blocks = &record.blocks;
        let hashes: Vec<_> = blocks.iter().map(|b| hex::encode(&b.hash)).collect();
        // Batched presence check rather than probing one
        // hash at a time — most of a hydration's blocks are typically
        // already-known-missing (that's the point of a placeholder), so
        // this collapses what would otherwise be N separate local-storage
        // calls interleaved with network fetches into one upfront query.
        let present = match self.store.present_blocks(&hashes) {
            Ok(present) => present,
            Err(e) => return Err(e.into()),
        };
        // Batched alongside `present_blocks` above, for the same reason --
        // calling the single-hash `group_has_block_provenance` once per
        // block would cost up to hundreds of separate SQLite round-trips
        // for one large file's worth of already-present blocks. `provenance_hashes` holds
        // the SUBSET of `block.hash` values with recorded provenance for
        // this group; a block whose hash isn't in this set has none (same
        // meaning as the single-hash call returning `false`).
        let provenance_hashes: std::collections::HashSet<Vec<u8>> =
            match self.state.group_has_block_provenance_batch(
                group_id,
                &blocks.iter().map(|b| b.hash.clone()).collect::<Vec<_>>(),
            ) {
                Ok(set) => set,
                Err(e) => return Err(e),
            };
        // Durability evidence:
        // `block_fetch_refusals` evidence must be bound to the EXACT
        // version it is about, not just the path -- a refusal recorded
        // against an older version must never be read as evidence about a
        // newer one that superseded it. That version is the caller's, and
        // arrives as `version_hash`.
        let current_version_hash_hex = version_hash.to_hex();
        let mut all_present = true;
        let concurrency = block_fetch_concurrency();
        // Bounded-concurrency block fetch rather than a strictly
        // one-at-a-time loop: per-block round-trip latency
        // (not transport throughput) dominates end-to-end time once bulk
        // bytes move fast: `DEFAULT_BLOCK_SIZE` (128 KiB) means a 1 GiB
        // file is up to ~8192 blocks, and even a few milliseconds of
        // unavoidable per-block control-plane/stream overhead compounds
        // linearly across that many strictly-sequential round-trips
        // (a 1 GiB transfer measured ~4.5ms/block sequentially).
        // `fetch_and_store_one_block` below is the per-block body (bounded
        // retry, fail-fast on `TimedOut`/`Redirect`/`Rejected`,
        // durability-fact recording); only how many run at once is
        // bounded here. `FuturesUnordered` of plain borrowed futures
        // (not `tokio::spawn`ed tasks) is deliberate: these are pure I/O-
        // bound awaits, need no separate task/thread, and dropping the
        // whole `FuturesUnordered` (e.g. on this function's own early
        // `Err` return below) cleanly cancels every still-in-flight fetch
        // with no detached background work left behind.
        // Factored out of the `FuturesUnordered` type below (clippy
        // type_complexity): a pinned, boxed, borrowed block-fetch future.
        type BlockFetchFuture<'a> = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            yadorilink_peer_session::convergence_driver::FetchedBlock,
                            PeerSessionError,
                        >,
                    > + Send
                    + 'a,
            >,
        >;
        let mut in_flight: FuturesUnordered<BlockFetchFuture<'_>> = FuturesUnordered::new();
        // Set once a block is confirmed missing after its own bounded
        // retries -- the equivalent of a sequential loop's `break`: this peer
        // has already shown it cannot supply this path's content, so
        // launching further fetches against it only adds latency for a
        // result already known to be `false`. Blocks already in flight
        // when this flips are still awaited to completion in the drain
        // loop below -- only launching NEW ones stops.
        let mut give_up = false;
        // Hashes are no longer collected per call. They accumulate in `pool.durable`
        // as batches commit -- across every file of the pass, not just this
        // one -- and the pass owner flushes them through ONE batched
        // `record_group_block_provenance` call. A hash reaches that field
        // only from a batch that already returned `Ok`, so provenance still
        // trails durability; and it is kept regardless of whether THIS
        // file's attempt ends `Ok(false)` or `Err`, so a block already made
        // durable is never re-fetched because one of its siblings failed.
        //
        // A hard per-block error (transport failure, a panicked
        // `store.put`/index-write task) used to `return Err(e)` immediately
        // -- now deferred until after the provenance flush below, so
        // sibling blocks that already succeeded in THIS call keep their
        // provenance rather than losing it to an unrelated later failure.
        // First error wins; `give_up` is also set so no further NEW
        // fetches launch, matching `Missing`'s own fail-fast behavior.
        let mut fatal_error: Option<PeerSessionError> = None;
        for (block, already_present) in blocks.iter().zip(present) {
            // A physical hit may belong only to another group. Treat it as
            // missing until this group has independently obtained the
            // bytes -- OR an earlier file in this SAME bounded
            // reconciliation window already fetched it this call (durably
            // committed, provenance flush merely deferred to the batch
            // boundary): see `ReconcileProvenanceBatch`'s own doc comment
            // for why that is provenance-equivalent for this attempt.
            let pending_provenance = reconcile_batch.is_some_and(|b| b.already_known(&block.hash));
            if already_present && (provenance_hashes.contains(&block.hash) || pending_provenance) {
                continue; // already held — dedup, no network round-trip
            }
            // An earlier file in THIS pass already pulled these exact bytes
            // and they are sitting in the pool, committed or not. Fetching
            // them again would cost a second network round-trip for content
            // this device already has in hand. Not treated as "held": the
            // hash still becomes provenance-eligible only through its
            // batch, so a failed commit leaves both files unpublishable and
            // re-fetched, rather than one of them believing it holds bytes
            // that were never written.
            if pool.fetched.contains(&block.hash) {
                continue;
            }
            if give_up {
                all_present = false;
                continue;
            }
            if in_flight.len() >= concurrency {
                if let Some(result) = in_flight.next().await {
                    self.absorb_fetch_result(
                        driver,
                        result,
                        pool,
                        group_id,
                        file_path,
                        &current_version_hash_hex,
                        &mut all_present,
                        &mut give_up,
                        &mut fatal_error,
                        call_timer,
                    )
                    .await;
                }
            }
            if give_up {
                continue;
            }
            in_flight.push(driver.fetch_block(group_id, file_path, block, block_response_timeout));
        }
        while let Some(result) = in_flight.next().await {
            self.absorb_fetch_result(
                driver,
                result,
                pool,
                group_id,
                file_path,
                &current_version_hash_hex,
                &mut all_present,
                &mut give_up,
                &mut fatal_error,
                call_timer,
            )
            .await;
        }

        // Nothing is drained here, deliberately. Whatever this file's
        // blocks did not fill stays pending so the NEXT file's blocks can
        // share the same barrier -- which is the entire point, since a
        // tiny-file workload is one block per file and a pool drained per
        // file could never batch anything. The pass owner drains once, and
        // only hashes from batches that already returned `Ok` become
        // provenance-eligible, so the ordering contract is unchanged.
        //
        // `all_present` here therefore means "every block is either already
        // held or has been fetched and handed to the pool", not "every
        // block is durable". The caller reconciles that against the drain's
        // own outcome; `ensure_blocks_present` does it immediately, the
        // cross-file pass at the end of its loop.
        match fatal_error {
            Some(e) => Err(e),
            None => Ok(all_present),
        }
    }

    pub async fn materialize(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        payload: &MaterializationPayload,
        policy: MaterializationPolicy,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
    ) -> Result<MaterializeResult, PeerSessionError> {
        let record = payload.record();
        let mut satisfied: Option<BlockRequirement> = None;
        loop {
            let outcome = self
                .materialize_local(
                    group_id,
                    payload,
                    policy,
                    origin_device_id,
                    authoring,
                    satisfied.as_ref(),
                    None,
                )
                .await?;
            let requirement = match outcome {
                LocalMaterializeOutcome::Concluded(result) => return Ok(result),
                LocalMaterializeOutcome::NeedBlocks(requirement) => requirement,
            };
            debug_assert!(
                satisfied.is_none(),
                "the local core asked for blocks twice; it must settle or decline after one                  attempt, or this loop would poll the block lane"
            );
            if satisfied.is_some() {
                return Ok(MaterializeResult::RetryRequired);
            }
            // Every block this attempt does obtain is stored durably and keeps
            // its provenance, whatever happens to its siblings -- so a partial
            // result is progress the next attempt does not repeat, not work
            // thrown away.
            tokio::time::timeout(
                Tuning::BULK_MATERIALIZE_TIMEOUT,
                self.ensure_blocks_present(
                    driver,
                    group_id,
                    &record.path,
                    record,
                    &requirement.version_hash,
                    Tuning::BULK_FETCH_RESPONSE_TIMEOUT,
                ),
            )
            .await
            .map_err(|_elapsed| PeerSessionError::HydrationFailed(record.path.clone()))??;
            satisfied = Some(requirement);
        }
    }

    /// Fetch every block this pass is going to want, and record what was
    /// observed for each path before its request went out.
    ///
    /// One bounded attempt per path. A path whose content does not arrive is
    /// still returned: the pass needs its before-picture either way, and it is
    /// what tells the pass to record a retriable placeholder rather than ask
    /// again. Provenance for everything obtained is flushed once, here, so the
    /// pass never publishes a row whose blocks this group cannot prove it
    /// holds.
    ///
    /// `call_timer` is the caller's own whole-attempt timer, not one created
    /// here: this is where an attempt's block fetching actually happens, so
    /// a timer scoped to this function alone is dropped before anything
    /// reports it (see `reconcile_paths_directly`'s own comment).
    pub(crate) async fn obtain_missing_content(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        paths: &std::collections::BTreeSet<String>,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<HashMap<String, BlockRequirement>, PeerSessionError> {
        let shape = PrefetchShape::Overlapped { fetches_in_flight: block_fetch_concurrency() };
        let (requirements, _outcomes) =
            self.obtain_missing_content_with(driver, group_id, paths, call_timer, shape).await?;
        Ok(requirements)
    }

    /// [`Self::obtain_missing_content`] with the fetch stage's shape chosen
    /// by the caller, also reporting how each wanted path's fetching ended.
    pub(crate) async fn obtain_missing_content_with(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        paths: &std::collections::BTreeSet<String>,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
        shape: PrefetchShape,
    ) -> Result<
        (HashMap<String, BlockRequirement>, std::collections::BTreeMap<String, PathPrefetch>),
        PeerSessionError,
    > {
        // On-demand is a promise about bytes: track every path and version a
        // peer publishes, fetch content only when something asks. This pass
        // is not something asking -- it runs on every reconnect and after
        // every unrelated commit, for every path in the group, so fetching
        // here would fill an on-demand folder up simply by staying connected.
        //
        // `materialize_local` already respects the policy and lands these
        // rows at `Remote`, which is why the state is right even today
        // and only the block store gives the bypass away. It is the one
        // remaining content fetch that never consults the policy at all.
        //
        // An explicit hydration is unaffected: it enters through
        // `hydration.rs` and `ensure_blocks_present`, not through this pass.
        // A group with no link row at all is left to fetch, matching every
        // other consumer's reading of `None` as "not on-demand" rather than
        // as a refusal. `materialize_local` reads the policy the same way, so
        // the two readings of "on-demand does not fetch" stay identical.
        if matches!(
            self.state.materialization_policy_for_group(group_id),
            Ok(Some(MaterializationPolicy::OnDemand))
        ) {
            return Ok(Default::default());
        }
        // Prefetch and the pass that materializes what it fetched read one
        // authority: both come from the native plan.
        let wanted = self.planned_missing_content(group_id, paths)?;
        if wanted.is_empty() {
            return Ok(Default::default());
        }
        let batch = Arc::new(ReconcileProvenanceBatch::new());
        // ONE pool for the whole pass, not one per file. A tiny-file
        // workload is exactly one block per file, so a pool that drained at
        // each file boundary could never batch anything: 2000 one-block
        // files produced 2000 batches of one, and therefore 2000 durability
        // barriers, measured end to end on two real daemons. Pooling across
        // the pass is what lets the block store's group commit do the job
        // it was built for -- the local capture side reached the same
        // conclusion, which is why `ScanBlockStaging` pools across files
        // rather than per file.
        let mut pool = ReceiveCommitPool::new(group_id, Some(Arc::clone(&batch)));
        let outcomes = match shape {
            PrefetchShape::Overlapped { fetches_in_flight } => {
                self.prefetch_overlapped(
                    driver,
                    group_id,
                    &wanted,
                    fetches_in_flight,
                    &batch,
                    call_timer,
                    &mut pool,
                )
                .await
            }
            #[cfg(test)]
            PrefetchShape::Serial => {
                self.prefetch_serially(driver, group_id, &wanted, &batch, call_timer, &mut pool)
                    .await
            }
        };
        // Everything still pending becomes durable here, and only now is
        // anything provenance-eligible. A file whose blocks are still in an
        // uncommitted batch has no provenance, so the pass cannot publish a
        // row for it -- which is exactly the ordering requirement, expressed
        // through the gate that already existed rather than a second one.
        self.pool_drain(driver, &mut pool, Some(call_timer)).await;
        if let Some(error) = &pool.fatal {
            // Not this pass's failure any more than a per-path fetch error
            // is: the paths whose blocks did commit still converge, and the
            // rest are absent, which the pass already knows how to record.
            tracing::debug!(
                group_id,
                %error,
                "a receive-side durability commit failed; leaving the affected paths for a \
                 later pass"
            );
        }
        // Before the pass publishes anything: a block this device holds but
        // cannot prove this group obtained is not this group's to serve.
        let obtained = std::mem::take(&mut pool.durable);
        if !obtained.is_empty() {
            self.flush_provenance_hashes(group_id, obtained, Some(call_timer)).await?;
        }
        let outcomes = wanted
            .iter()
            .zip(outcomes)
            .map(|(planned, outcome)| (planned.requirement.path.clone(), outcome))
            .collect();
        let requirements =
            wanted.into_iter().map(|p| (p.requirement.path.clone(), p.requirement)).collect();
        Ok((requirements, outcomes))
    }

    /// The fetch stage: every wanted path's missing blocks, drawn through ONE
    /// allowance of `fetches_in_flight` concurrent requests to the peer.
    ///
    /// The allowance is per attempt, not per path. A window of one-block
    /// files is the common receive workload, and an allowance per path gave
    /// each of them exactly one request in flight: the attempt spent its
    /// time waiting on one round trip after another while the peer sat
    /// idle. Sharing one allowance keeps the peer's load and this side's
    /// memory bounded by the same number whatever the files look like --
    /// one large file or many small ones put the same number of requests on
    /// the wire.
    ///
    /// Paths take their turn in plan order, and a path is admitted only when
    /// a request slot is free for it: that is the moment its plan is checked
    /// for staleness and its held blocks are subtracted, so neither check
    /// runs early against state the attempt's own earlier fetches are still
    /// changing.
    ///
    /// A block two paths both need is asked for once when the answer is the
    /// block itself. The second path joins the request already in flight; a
    /// block an earlier path already fetched this attempt is not asked for
    /// again at all (`pool.fetched`). Neither grants anything: provenance
    /// still comes only from a committed batch. Any other answer is only
    /// about the requester: the peer authorises each request against the
    /// path it names, so a path that no longer references the block is told
    /// the peer does not have it even when a sibling path would be served.
    /// A joined path therefore asks again under its own name rather than
    /// inherit a not-found, a refusal or an error that was never about it.
    ///
    /// Every answer is absorbed here, in this one loop, which is the only
    /// code that touches `pool`. The fetches are plain futures owned by this
    /// call, never spawned tasks, so dropping the attempt drops every
    /// request in flight with it.
    #[allow(clippy::too_many_arguments)]
    async fn prefetch_overlapped(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        wanted: &[PlannedRequirement],
        fetches_in_flight: usize,
        batch: &ReconcileProvenanceBatch,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
        pool: &mut ReceiveCommitPool,
    ) -> Vec<PathPrefetch> {
        type Fetch<'a> = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = (
                            usize,
                            &'a yadorilink_replica_domain::file::BlockInfo,
                            Result<
                                Result<
                                    yadorilink_peer_session::convergence_driver::FetchedBlock,
                                    PeerSessionError,
                                >,
                                tokio::time::error::Elapsed,
                            >,
                        ),
                    > + Send
                    + 'a,
            >,
        >;
        let allowance = fetches_in_flight.max(1);
        let mut states: Vec<PathFetchState> =
            wanted.iter().map(|_| PathFetchState::default()).collect();
        let mut in_flight: FuturesUnordered<Fetch<'_>> = FuturesUnordered::new();
        // Every hash with a joinable request on the wire: who asked, and the
        // paths waiting on its answer.
        type PathBlock<'a> = (usize, &'a yadorilink_replica_domain::file::BlockInfo);
        let mut waiting: HashMap<Vec<u8>, (usize, Vec<PathBlock<'_>>)> = HashMap::new();
        // Joined paths whose shared answer was not the block: each asks
        // again, under its own path, before any new work starts.
        let mut own_requests: std::collections::VecDeque<PathBlock<'_>> =
            std::collections::VecDeque::new();
        let mut next_path = 0;
        let mut current: Option<(usize, std::collections::VecDeque<_>)> = None;
        loop {
            while in_flight.len() < allowance {
                let own_request = !own_requests.is_empty();
                let next = own_requests.pop_front().or_else(|| {
                    current
                        .as_mut()
                        .and_then(|(index, queue)| queue.pop_front().map(|block| (*index, block)))
                });
                let Some((index, block)) = next else {
                    if next_path == wanted.len() {
                        break;
                    }
                    let index = next_path;
                    next_path += 1;
                    let blocks =
                        self.admit_path(group_id, &wanted[index], batch, &mut states[index]);
                    current = Some((index, blocks.into()));
                    continue;
                };
                let state = &mut states[index];
                if pool.fetched.contains(&block.hash) {
                    continue;
                }
                // Checked before joining, so a path that already gave up
                // keeps the outcome it gave up with.
                if state.give_up {
                    state.incomplete = true;
                    continue;
                }
                if state.deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                    state.timed_out = true;
                    state.give_up = true;
                    continue;
                }
                match waiting.get_mut(&block.hash) {
                    Some((_, joined)) if !own_request => {
                        joined.push((index, block));
                        continue;
                    }
                    Some(_) => {}
                    None => {
                        waiting.insert(block.hash.clone(), (index, Vec::new()));
                    }
                }
                let file_path = wanted[index].requirement.path.as_str();
                in_flight.push(Box::pin(async move {
                    let fetched = tokio::time::timeout(
                        Tuning::BULK_MATERIALIZE_TIMEOUT,
                        driver.fetch_block(
                            group_id,
                            file_path,
                            block,
                            Tuning::BULK_FETCH_RESPONSE_TIMEOUT,
                        ),
                    )
                    .await;
                    (index, block, fetched)
                }));
            }
            let Some((requester, block, fetched)) = in_flight.next().await else { break };
            let joined = match waiting.get(&block.hash) {
                Some((asked_by, _)) if *asked_by == requester => {
                    waiting.remove(&block.hash).map(|(_, joined)| joined).unwrap_or_default()
                }
                _ => Vec::new(),
            };
            let delivered = self
                .absorb_shared_fetch(
                    driver,
                    group_id,
                    wanted,
                    requester,
                    fetched,
                    &mut states,
                    pool,
                    call_timer,
                )
                .await;
            if !delivered {
                own_requests.extend(joined);
            }
        }
        wanted
            .iter()
            .zip(states)
            .map(|(planned, state)| state.outcome(group_id, &planned.requirement.path))
            .collect()
    }

    /// A path's turn has come: whether its plan still stands, and which of
    /// its blocks it still has to ask for.
    fn admit_path<'a>(
        &self,
        group_id: &str,
        planned: &'a PlannedRequirement,
        batch: &ReconcileProvenanceBatch,
        state: &mut PathFetchState,
    ) -> Vec<&'a yadorilink_replica_domain::file::BlockInfo> {
        let requirement = &planned.requirement;
        // An earlier path's fetch can take long enough for a newer version
        // to supersede this one. Its content would only be a wasted request
        // and an unreferenced block: the pass re-resolves this path anyway.
        let heads =
            self.state.database().read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::native_store::native_heads_at(
                    conn,
                    &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned()),
                    &planned.source_path,
                )
            });
        match heads {
            Ok(heads) if heads.iter().any(|h| h.payload.version == requirement.version_hash) => {}
            Ok(_) => {
                state.stale = true;
                return Vec::new();
            }
            Err(error) => {
                state.error =
                    Some(PeerSessionError::from(crate::sync_error::SyncError::from(error)));
                return Vec::new();
            }
        }
        let blocks = &requirement.record.blocks;
        let hashes: Vec<_> = blocks.iter().map(|b| hex::encode(&b.hash)).collect();
        let held = self.store.present_blocks(&hashes).map_err(PeerSessionError::from).and_then(
            |present| {
                let provenance = self.state.group_has_block_provenance_batch(
                    group_id,
                    &blocks.iter().map(|b| b.hash.clone()).collect::<Vec<_>>(),
                )?;
                Ok((present, provenance))
            },
        );
        let (present, provenance) = match held {
            Ok(held) => held,
            Err(error) => {
                state.error = Some(error);
                return Vec::new();
            }
        };
        state.deadline = Some(tokio::time::Instant::now() + Tuning::BULK_MATERIALIZE_TIMEOUT);
        // A physical hit may belong only to another group: it counts only
        // with this group's provenance, recorded or pending behind this
        // attempt's own batch -- the same rule `ensure_blocks_present_core`
        // applies.
        blocks
            .iter()
            .zip(present)
            .filter(|(block, present)| {
                !(*present
                    && (provenance.contains(&block.hash) || batch.already_known(&block.hash)))
            })
            .map(|(block, _)| block)
            .collect()
    }

    /// Applies one answer to the path that asked for it, returning whether
    /// the answer was the block itself -- the only answer that also settles
    /// the paths that joined the request. Its bytes go to the pool once,
    /// however many paths share the block.
    #[allow(clippy::too_many_arguments)]
    async fn absorb_shared_fetch(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        wanted: &[PlannedRequirement],
        requester: usize,
        fetched: Result<
            Result<yadorilink_peer_session::convergence_driver::FetchedBlock, PeerSessionError>,
            tokio::time::error::Elapsed,
        >,
        states: &mut [PathFetchState],
        pool: &mut ReceiveCommitPool,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> bool {
        use yadorilink_peer_session::convergence_driver::BlockFetch;
        let requirement = &wanted[requester].requirement;
        let state = &mut states[requester];
        let fetched = match fetched {
            Ok(Ok(fetched)) => fetched,
            Ok(Err(error)) => {
                state.give_up = true;
                if state.error.is_none() {
                    state.error = Some(error);
                }
                return false;
            }
            Err(_elapsed) => {
                state.timed_out = true;
                state.give_up = true;
                return false;
            }
        };
        call_timer.add_block_fetch_wait(fetched.wire_wait);
        match fetched.outcome {
            BlockFetch::Fetched { hash, data } => {
                call_timer.add_block_fetched();
                self.pool_push(
                    driver,
                    pool,
                    PendingBlock {
                        hash,
                        data,
                        path: requirement.path.clone(),
                        version_hex: requirement.version_hash.to_hex(),
                    },
                    Some(call_timer),
                )
                .await;
                true
            }
            BlockFetch::Missing => {
                state.incomplete = true;
                state.give_up = true;
                false
            }
            BlockFetch::VerifiedRefusal { reason } => {
                self.record_refusal(
                    driver,
                    group_id,
                    &requirement.path,
                    &requirement.version_hash.to_hex(),
                    &reason,
                );
                state.incomplete = true;
                state.give_up = true;
                false
            }
        }
    }

    /// The fetch stage as it was before it overlapped paths: one path at a
    /// time, in plan order. Kept as the reference the overlapped stage is
    /// compared against.
    #[cfg(test)]
    async fn prefetch_serially(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        wanted: &[PlannedRequirement],
        batch: &ReconcileProvenanceBatch,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
        pool: &mut ReceiveCommitPool,
    ) -> Vec<PathPrefetch> {
        let mut outcomes = Vec::with_capacity(wanted.len());
        for PlannedRequirement { requirement, .. } in wanted {
            // Bounded per path. An unreachable or unhelpful peer leaves this
            // path's content absent, which the pass then records durably --
            // it never becomes a wait.
            let fetched = tokio::time::timeout(
                Tuning::BULK_MATERIALIZE_TIMEOUT,
                self.ensure_blocks_present_collecting(
                    driver,
                    group_id,
                    &requirement.path,
                    &requirement.record,
                    &requirement.version_hash,
                    Tuning::BULK_FETCH_RESPONSE_TIMEOUT,
                    batch,
                    call_timer,
                    pool,
                ),
            )
            .await;
            // Hashes are not collected here: they land in `pool.durable`
            // when the batch carrying them commits, which may be during a
            // LATER file's fetching or not until the pass drains. That
            // deferral is the point -- and it is also what keeps provenance
            // strictly behind durability, since a hash cannot reach
            // `pool.durable` before the write it attests to returned `Ok`.
            outcomes.push(match fetched {
                Ok(Ok(true)) => PathPrefetch::Obtained,
                Ok(Ok(false)) => PathPrefetch::Incomplete,
                Ok(Err(error)) => {
                    log_unobtained(group_id, &requirement.path, &error);
                    PathPrefetch::Failed
                }
                Err(_elapsed) => {
                    log_timed_out(group_id, &requirement.path);
                    PathPrefetch::TimedOut
                }
            });
        }
        outcomes
    }

    /// Hands whatever is pending to the store as one batch, first making
    /// room by settling commits down to `MAX_COMMITS_IN_FLIGHT - 1`.
    ///
    /// Settling before launching rather than after is what keeps fetching
    /// overlapped with flushing: an in-flight `FuturesUnordered` makes no
    /// progress while its driving task is parked, so a design that awaited
    /// each commit inline would stall every concurrent fetch for the length
    /// of an fsync.
    async fn pool_commit_pending(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        pool: &mut ReceiveCommitPool,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) {
        if pool.pending.is_empty() {
            return;
        }
        while pool.commits.len() >= Tuning::MAX_COMMITS_IN_FLIGHT {
            match pool.commits.next().await {
                Some(joined) => self.absorb_commit_result(driver, joined, pool, call_timer),
                None => break,
            }
        }
        let batch = std::mem::take(&mut pool.pending);
        pool.pending_bytes = 0;
        let commit = self.spawn_commit(driver, batch, &pool.group_id, call_timer);
        pool.commits.push(commit);
    }

    /// Flushes everything still pending and waits for every commit to
    /// land. After this returns, `pool.durable` names exactly the blocks
    /// this pass made durable -- which is what makes it safe to record
    /// provenance for them and not before.
    async fn pool_drain(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        pool: &mut ReceiveCommitPool,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) {
        self.pool_commit_pending(driver, pool, call_timer).await;
        while let Some(joined) = pool.commits.next().await {
            self.absorb_commit_result(driver, joined, pool, call_timer);
        }
    }

    /// Takes one fetched block into the pool, and commits a batch if that
    /// filled one.
    ///
    /// Called from inside a file's fetch loop but operating on a pool that
    /// outlives that file, which is what lets one barrier serve blocks from
    /// many files.
    async fn pool_push(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        pool: &mut ReceiveCommitPool,
        block: PendingBlock,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) {
        pool.pending_bytes += block.data.len() as u64;
        pool.fetched.insert(block.hash.clone());
        pool.pending.push(block);
        if pool.pending.len() >= Tuning::RECEIVE_COMMIT_BATCH_BLOCKS
            || pool.pending_bytes >= Tuning::RECEIVE_COMMIT_BATCH_BYTES
        {
            self.pool_commit_pending(driver, pool, call_timer).await;
        }
    }

    /// Periodic native resync's local repair backstop. A heads announce keeps
    /// network catch-up proportional to divergence, but it carries no file
    /// metadata when both sides already know the same heads. Re-run the
    /// ordinary reconcile path only for locally tracked repair candidates so
    /// eager live records demoted to placeholders/hydrating still rehydrate
    /// without making every peer session scan and re-query the whole group.
    /// Returns `Ok(true)` if this call actually ran the audit (whether or
    /// not it found anything to do), `Ok(false)` if it was skipped because
    /// another audit for the same group is already in flight
    /// (`MaterializationAuditGuard` contention). Callers that use a skip as
    /// a signal for their own bookkeeping (the Convergence Engine's
    /// `run_once`, see `engine.rs`) need this distinction: a caller that
    /// cannot tell a skip from "ran and made no progress" would otherwise
    /// treat a contended tick as a failed materialization attempt and apply
    /// backoff for it, needlessly delaying a job that never actually got a
    /// chance to run this tick.
    pub async fn reconcile_local_materialization_audit(
        self: Arc<Self>,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
    ) -> Result<bool, PeerSessionError> {
        let audit_attempt_id = next_audit_attempt_id();
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            audit_attempt_id,
            "materialization audit attempt starting"
        );
        // This audit re-drives materialization, so it needs the same
        // fail-closed link gate the incoming-batch path uses: for an unlinked
        // group there is no folder to repair towards, and re-projecting into
        // one would be exactly the write the unlink was meant to stop.
        if !matches!(
            self.state.directory_link_gate_for_group(group_id)?,
            Some(LinkGate::Live { .. })
        ) {
            return Ok(true);
        }
        // Repair re-materializes files, so it waits for startup capture too.
        if !self.startup_admits_peer_apply(group_id) {
            return Ok(false);
        }
        // Ordinary desired-state projection has exactly one scheduling
        // source (`projection_obligations`) and one driver (the
        // Convergence Engine's own claim/reconcile loop) -- this periodic
        // audit no longer independently re-projects unprojected history.
        // What remains here are the genuinely distinct maintenance
        // responsibility: explicit repair-candidate
        // re-materialization. Held for the whole
        // remainder of this audit -- unlike the old reproject-backstop
        // era, nothing here runs an unbounded number of
        // `reconcile_group_paths` calls, so there is no reason to release
        // and re-acquire between steps.
        let Some(_guard) = MaterializationAuditGuard::try_acquire(&self.state, group_id) else {
            return Ok(false);
        };

        let paths = self.state.list_materialization_repair_candidates(group_id)?;
        // Names every candidate
        // path this device's own audit considered repair-eligible this
        // attempt -- see the tracked comment on `randomized_soak_converges_
        // with_no_leaks_or_stuck_state` in `topology_soak_lane.rs`.
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            audit_attempt_id,
            ?paths,
            "materialization audit: repair-candidate paths"
        );
        if paths.is_empty() {
            return Ok(true);
        }

        // The payloads of the audit's own candidates cannot be built from the
        // index alone; the authority's own plan
        // is what re-drives them, fetching what is missing from the peer.
        let seeds: std::collections::BTreeSet<String> = paths.iter().cloned().collect();
        let call_timer = crate::local_convergence::call_timer::ReconcileCallTimer::new();
        let prefetched = self.obtain_missing_content(driver, group_id, &seeds, &call_timer).await?;
        self.reconcile_group_paths_native(
            group_id,
            seeds,
            driver.peer_device_id(),
            &prefetched,
            None,
            &call_timer,
        )
        .await?;
        Ok(true)
    }

    /// Hands one batch of fetched blocks to the block store off the async
    /// runtime, as a single durability barrier.
    ///
    /// The hash check here is not redundant with the wire checks: the
    /// receive path compares the peer's ECHOED header hash against the one
    /// it asked for, which is only the peer's own claim about its payload.
    /// `LocallyHashedBlock` hashes the bytes that actually arrived, and
    /// this is the first point where those two can be compared. Before
    /// batching, the per-block `store.put` computed the same hash and
    /// simply discarded it, so a peer returning the wrong bytes had them
    /// stored under their own (different) key while this device recorded
    /// provenance for the key it had asked for -- attesting to a block it
    /// did not hold. Mismatches are dropped from the batch and reported as
    /// `rejected`, never stored and never provenanced.
    ///
    /// The stale-refusal clears ride along in this same blocking hop, one
    /// per distinct `(path, version)` the batch carried rather than one per
    /// block. Those keys hold no hash, so the old per-block version issued
    /// the byte-for-byte identical SQLite write once for every block of a
    /// file; deduplicating them is the same meaning for a fraction of the
    /// writes, and it is what lets a batch span files without either
    /// dropping a clear or repeating one.
    fn spawn_commit(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        batch: Vec<PendingBlock>,
        group_id: &str,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) -> BlockingHandle<CommittedBatch> {
        let store = self.store.clone();
        let blocks = batch.len();
        let attributed = call_timer.is_some();
        let index_state = self.state.clone();
        let refusal_peer = driver.peer_device_id().to_string();
        let refusal_group_id = group_id.to_string();
        spawn_blocking(move || {
            let started = std::time::Instant::now();
            let mut prepared = Vec::with_capacity(blocks);
            let mut hashes = Vec::with_capacity(blocks);
            let mut rejected = Vec::new();
            let mut refusal_keys: Vec<(String, String)> = Vec::new();
            for block in batch {
                let hashed =
                    yadorilink_local_storage::LocallyHashedBlock::from_bytes(block.data.to_vec());
                if hashed.hash().as_bytes() != hex::encode(&block.hash).as_bytes() {
                    rejected.push(block.hash);
                    continue;
                }
                let key = (block.path, block.version_hex);
                if !refusal_keys.contains(&key) {
                    refusal_keys.push(key);
                }
                hashes.push(block.hash);
                prepared.push(hashed);
            }
            let error = store.put_prepared_batch(&prepared).err();
            let elapsed = started.elapsed();
            // Only after a successful commit: a batch that failed proves
            // nothing about what this peer holds.
            if error.is_none() {
                for (path, version) in &refusal_keys {
                    let cleared = index_state.clear_block_fetch_refusal(
                        &refusal_group_id,
                        path,
                        version,
                        &refusal_peer,
                    );
                    // Same disposition as before: a failed refusal clear is
                    // logged and tolerated, never fatal to this fetch.
                    if let Err(e) = cleared {
                        tracing::warn!(
                            file_path = %path,
                            error = %e,
                            "failed to clear a stale block fetch refusal after a successful fetch"
                        );
                    }
                }
            }
            CommittedBatch {
                hashes,
                rejected,
                error,
                elapsed: if attributed { Some(elapsed) } else { None },
            }
        })
    }
}

/// How the prefetch stage of one attempt fetches the blocks its paths want.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PrefetchShape {
    /// Every wanted path's blocks drawn through one shared allowance of
    /// `fetches_in_flight` concurrent requests to the peer, so paths overlap
    /// with each other and not only blocks within one path.
    Overlapped { fetches_in_flight: usize },
    /// One path at a time, in plan order: the stage as it was before paths
    /// overlapped, kept as the reference the overlapped stage must agree
    /// with.
    #[cfg(test)]
    Serial,
}

/// How one wanted path's fetching ended in a prefetch attempt.
///
/// None of these is the pass's failure: the pass re-resolves every path and
/// records a retriable placeholder for content that did not arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PathPrefetch {
    /// Every block is held, or was fetched and handed to the commit pool.
    Obtained,
    /// The peer did not supply some block.
    Incomplete,
    /// A transport or local error ended this path's fetching.
    Failed,
    /// The path's bounded attempt ran out of time.
    TimedOut,
    /// The version the path was planned for stopped being one of its source
    /// path's live heads before the path's turn came, so nothing was asked
    /// for it.
    Stale,
}

/// One wanted path's progress through [`PrefetchShape::Overlapped`].
#[derive(Default)]
struct PathFetchState {
    /// Some block will not arrive from this peer this attempt; no further
    /// request is started for this path.
    give_up: bool,
    incomplete: bool,
    timed_out: bool,
    stale: bool,
    /// The path's bounded attempt, counted from its admission.
    deadline: Option<tokio::time::Instant>,
    /// The first error that ended this path's fetching: a local one while
    /// admitting it, or a transport error answering its own request.
    error: Option<PeerSessionError>,
}

impl PathFetchState {
    fn outcome(self, group_id: &str, path: &str) -> PathPrefetch {
        if self.stale {
            return PathPrefetch::Stale;
        }
        if let Some(error) = &self.error {
            log_unobtained(group_id, path, error);
            return PathPrefetch::Failed;
        }
        if self.timed_out {
            log_timed_out(group_id, path);
            return PathPrefetch::TimedOut;
        }
        if self.incomplete {
            return PathPrefetch::Incomplete;
        }
        PathPrefetch::Obtained
    }
}

fn log_unobtained(group_id: &str, path: &str, error: &dyn std::fmt::Display) {
    // Neither a timeout nor a fetch error is the pass's failure: every
    // other path still converges, and this one is absent, which the pass
    // already knows how to record.
    tracing::debug!(
        group_id,
        path,
        %error,
        "could not obtain this path's content from this peer; leaving it for a later pass"
    );
}

fn log_timed_out(group_id: &str, path: &str) {
    tracing::debug!(
        group_id,
        path,
        "timed out obtaining this path's content from this peer; leaving it for a later pass"
    );
}
