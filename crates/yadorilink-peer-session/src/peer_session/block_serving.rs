//! Source side of the block stream lane: examining, admitting (through the
//! shared `BlockServeEngine`), and answering a peer's `BlockRequest`.

use std::sync::Arc;

use bytes::Bytes;

use crate::error::PeerSessionError;

use super::{
    compress_block, spawn_blocking, PeerSyncSession, MAX_BLOCK_SIZE, NO_VERIFIED_PROVENANCE_REASON,
};

/// One `BlockRequest`'s worth of examination-admission slot, held so
/// `handle_block_request` can release it (a plain `drop`) once examination
/// finishes, before dispatch/service begins. `None` only when no
/// `BlockServeEngine` was installed at all (see `run`'s recv loop, the
/// `None` arm of its own `block_serve_engine()` match) — there is nothing
/// to hold in that case, since `try_begin_examination` was never called.
struct BlockExaminationPermits {
    _device_wide: Option<crate::block_serve::ExaminationPermit>,
}

/// `handle_block_request`'s combined verdict from `self.
/// block_serve_authorizer.authorize_block_serve` -- see
/// `block_request_checks_off_runtime`'s own
/// doc comment for why that single semantic check is run as one offloaded
/// unit instead of the storage reads it used to be assembled from here.
enum BlockRequestCheckOutcome {
    /// Referenced by this device's own record of the file (or native state/
    /// retained-version fallback), and the peer has verified provenance --
    /// the request may proceed to dispatch/serve. `declared_size` is the
    /// block's own declared size when cheaply known, `None` when it must
    /// fall back to a pessimistic estimate -- see `authorize_block_serve`'s
    /// own doc comment.
    Ok { declared_size: Option<u32> },
    /// Not referenced by the requested file's live record, native heads, or
    /// retained versions. Answered `dont_have`, not `rejected` -- see the
    /// call site's own comment on why a retry may still succeed.
    NotReferenced,
    /// Referenced, but this peer has no verified provenance for the group.
    /// Answered `rejected` with `NO_VERIFIED_PROVENANCE_REASON`.
    NoProvenance,
}

/// How long a block stream may take to deliver its request header before it
/// is dropped. The device-wide examination budget is taken only after the
/// header arrives, so a peer that never sends one costs a task, not a permit.
const BLOCK_REQUEST_HEADER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

impl PeerSyncSession {
    /// Installs this session's device-wide block-serve engine, set once by
    /// `DaemonState` after construction — see `block_serve::BlockServeEngine`'s
    /// own doc comment for why this is a post-construction setter rather
    /// than a constructor parameter.
    pub fn set_block_serve_engine(&self, engine: Arc<crate::block_serve::BlockServeEngine>) {
        *self.block_serve_engine.lock().unwrap_or_else(|p| p.into_inner()) = Some(engine);
    }

    pub(super) fn block_serve_engine(&self) -> Option<Arc<crate::block_serve::BlockServeEngine>> {
        self.block_serve_engine.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Serve one inbound block stream -- always one arriving on the
    /// substrate's block lane (`sync_stack.rs`'s `serve_peer_lanes` in
    /// production; a fixture's own equivalent lane-serving loop in tests),
    /// never this session's own control channel, which no longer carries
    /// block traffic in either direction.
    ///
    /// One task per accepted stream, with no local queue in front of it,
    /// is the caller's own concern (both real callers spawn one task per
    /// accepted stream); cross-peer fairness and device-wide admission live
    /// in the shared `BlockServeEngine`, which every session funnels into.
    ///
    /// Reads the request header under [`BLOCK_REQUEST_HEADER_DEADLINE`] first
    /// and only then takes the device-wide examination budget any other
    /// request takes, answering `Busy` the same way when it cannot: the budget
    /// bounds this device's work, so it cannot depend on which transport the
    /// request came in on. Taking it before the header would let a peer that
    /// opens streams and never sends a header hold every permit.
    pub async fn serve_block_stream(
        self: Arc<Self>,
        stream: Box<dyn crate::ports::PeerBlockStream>,
    ) {
        let mut stream = stream;
        let read = tokio::time::timeout(
            BLOCK_REQUEST_HEADER_DEADLINE,
            stream.recv_message(yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES),
        )
        .await;
        let header = match read {
            Ok(Ok(header)) => header,
            Ok(Err(error)) => {
                // A requester that opened a stream and then went away
                // before saying what it wanted. Nothing to answer, and
                // nothing to record: this is what an abandoned fetch
                // looks like from here.
                tracing::debug!(%error, peer = %self.peer_device_id, "block stream ended before its request header");
                return;
            }
            Err(_) => {
                tracing::debug!(peer = %self.peer_device_id, "block stream sent no request header in time");
                return;
            }
        };
        match self.begin_block_examination() {
            Ok(permits) => self.serve_one_block_stream(stream, header, permits).await,
            Err(busy) => {
                let _ = self
                    .respond_to_block_request(
                        &mut *stream,
                        yadorilink_sync_wire::BlockResponseOutcomeFrame::Busy {
                            retry_after_ms: busy.retry_after_ms,
                            queue_depth: busy.queue_depth,
                        },
                        &[],
                    )
                    .await;
            }
        }
    }

    /// The device-wide examination budget for one incoming block request.
    ///
    /// Taken before the request is handed to a task, so one that cannot get a
    /// permit is answered `Busy` immediately rather than after paying for the
    /// checks the budget exists to bound.
    fn begin_block_examination(
        &self,
    ) -> Result<BlockExaminationPermits, crate::block_serve::ServeBusy> {
        match self.block_serve_engine() {
            Some(engine) => engine
                .try_begin_examination()
                .map(|device_wide| BlockExaminationPermits { _device_wide: Some(device_wide) }),
            // No engine wired yet: `handle_block_request` itself fails closed
            // on this (see `set_block_serve_engine`'s doc comment) -- serve
            // anyway so that fail-closed rejection still reaches the
            // requester.
            None => Ok(BlockExaminationPermits { _device_wide: None }),
        }
    }

    /// Decodes the already-read request `header` and answers it on `stream`.
    async fn serve_one_block_stream(
        &self,
        mut stream: Box<dyn crate::ports::PeerBlockStream>,
        header: Vec<u8>,
        examination_permits: BlockExaminationPermits,
    ) {
        let req = match self.codec.decode_block_request_header(&header) {
            Ok(req) => req,
            Err(error) => {
                tracing::warn!(%error, peer = %self.peer_device_id, "discarding a malformed block request header");
                let _ = self
                    .respond_to_block_request(
                        &mut *stream,
                        yadorilink_sync_wire::BlockResponseOutcomeFrame::Rejected {
                            reason: "malformed block request header".to_string(),
                        },
                        &[],
                    )
                    .await;
                return;
            }
        };
        if let Err(error) = self.handle_block_request(&mut *stream, req, examination_permits).await
        {
            tracing::warn!(%error, peer = %self.peer_device_id, "error handling block request");
        }
    }

    /// Sends one block response header on `stream`, then `body` (empty for
    /// every outcome but `Found`) and the FIN that ends this side of the
    /// exchange.
    ///
    /// There is deliberately no non-blocking counterpart, and there no
    /// longer needs to be one. When every reply shared the control stream's
    /// single outbound queue, a blocking send could be held up behind an
    /// unrelated backlog -- so a rejection discovered while holding a
    /// device-wide examination permit had to be best-effort or not sent at
    /// all. A response now goes out on the requester's own stream, so the
    /// only thing that can delay it is that same requester declining to
    /// read its own answer, and the only thing delayed is this one task.
    async fn respond_to_block_request(
        &self,
        stream: &mut dyn crate::ports::PeerBlockStream,
        outcome: yadorilink_sync_wire::BlockResponseOutcomeFrame,
        body: &[u8],
    ) -> Result<(), PeerSessionError> {
        let header = self
            .codec
            .encode_block_response_header(yadorilink_sync_wire::BlockResponseHeaderFrame {
                outcome,
            })
            .map_err(|e| PeerSessionError::InvalidInput(e.to_string()))?;
        stream.send_message(&header).await?;
        stream.send_body(body).await?;
        Ok(())
    }

    /// Hard rejection: an authorization or provenance failure discovered
    /// before any real serving would begin, which retrying is not expected
    /// to resolve (unlike `dont_have`'s race-prone "not referenced" case).
    async fn reject_block_request(
        &self,
        stream: &mut dyn crate::ports::PeerBlockStream,
        reason: &str,
    ) -> Result<(), PeerSessionError> {
        self.respond_to_block_request(
            stream,
            yadorilink_sync_wire::BlockResponseOutcomeFrame::Rejected {
                reason: reason.to_string(),
            },
            &[],
        )
        .await
    }

    async fn handle_block_request(
        &self,
        stream: &mut dyn crate::ports::PeerBlockStream,
        req: yadorilink_sync_wire::BlockRequestHeaderFrame,
        examination_permits: BlockExaminationPermits,
    ) -> Result<(), PeerSessionError> {
        // A block store is shared across all folder groups on this device,
        // so a hash by itself doesn't imply group
        // membership — without this check a peer could fetch any block
        // this device holds, from any group, by guessing/observing a
        // hash, regardless of what it's actually authorized to sync.
        //
        // `shares_group` is
        // called fresh on every single incoming request (this
        // function has no per-session cache of its own answer), and reads
        // `live_authorized_groups` rather than the construction-time
        // `shared_group_ids` snapshot — so a group edge revoked by a
        // netmap update that lands *after* this session started, and
        // *before* this particular request is processed, is already
        // reflected here, even though the connection this request arrived
        // over has not been torn down (that's a separate, independent
        // reaction to the same netmap update).
        // The lookup itself stays a local, in-memory
        // `Mutex`-guarded `HashSet` check — no coordination-plane round
        // trip is made per request, consistent with a push model.
        //
        // Every branch below returns before `handle_block_request_with_
        // credit`'s dispatch/serve phase, so it is still within
        // EXAMINATION: `examination_permits` is dropped before the answer
        // is sent, so an authorized-but-untrusted peer that keeps sending
        // requests doomed to fail one of these checks cannot hold a
        // device-wide examination slot open for as long as it declines to
        // read its own rejection.
        if !self.shares_group(&req.folder_group_id) {
            tracing::warn!(group_id = %req.folder_group_id, peer = %self.peer_device_id, "ignoring block request for unauthorized/unshared folder group");
            drop(examination_permits);
            return self
                .reject_block_request(stream, "requester is not authorized for this folder group")
                .await;
        }
        let declared_size = match self.block_request_checks_off_runtime(&req).await? {
            BlockRequestCheckOutcome::Ok { declared_size } => declared_size,
            BlockRequestCheckOutcome::NotReferenced => {
                tracing::warn!(
                    local_device_id = %self.local_device_id,
                    group_id = %req.folder_group_id,
                    path = %req.file_path,
                    peer = %self.peer_device_id,
                    hash = %hex::encode(&req.block_hash),
                    "refusing block request not referenced by the requested file record"
                );
                // Not a hard rejection: the requester's own record of this
                // path/hash may simply be racing this device's own in-flight
                // materialize/upsert (`ensure_blocks_present`'s bounded
                // `NOT_FOUND_RETRY_ATTEMPTS` exists specifically to absorb
                // that), so this answers `dont_have`, not `rejected` -- a
                // retry shortly after may well succeed.
                drop(examination_permits);
                return self
                    .respond_to_block_request(
                        stream,
                        yadorilink_sync_wire::BlockResponseOutcomeFrame::DontHave,
                        &[],
                    )
                    .await;
            }
            BlockRequestCheckOutcome::NoProvenance => {
                tracing::warn!(
                    local_device_id = %self.local_device_id,
                    group_id = %req.folder_group_id,
                    path = %req.file_path,
                    peer = %self.peer_device_id,
                    hash = %hex::encode(&req.block_hash),
                    "refusing block request without verified group provenance"
                );
                drop(examination_permits);
                return self.reject_block_request(stream, NO_VERIFIED_PROVENANCE_REASON).await;
            }
        };
        // Every check above (authorization, reference, provenance) is
        // shared regardless of what happens next. Serving itself always
        // goes through the credit-gated, coalesced path -- there is no
        // more direct-serve fallback. A session with no engine installed at
        // all (a programming error in this codebase's own construction --
        // every real `DaemonState`-backed session always has one; see
        // `set_block_serve_engine`'s doc comment) fails closed with
        // `Rejected` rather than a panic in this spawned per-stream task.
        //
        // EXAMINATION (everything above this line) is done -- release the
        // permit explicitly, here, rather than letting it ride along until
        // this whole function returns. `handle_block_request_with_credit`
        // below waits for a fair dispatch turn (up to `DISPATCH_WAIT_
        // BUDGET`), then does a possibly-gated disk read and sends the
        // response -- genuinely slow work that has nothing to do with
        // examination admission. Holding an examination permit through all
        // of that would let one busy-but-legitimate request tie up an
        // examination slot for far longer than examining it actually takes,
        // eating into the SAME budget meant to bound how fast NEW requests
        // can be examined -- exactly the failure mode named in this
        // struct's own doc: a peer whose requests are simply slow to
        // service (not malicious) could still starve other peers' requests
        // at the door for the whole service duration, not just the
        // examination one.
        drop(examination_permits);
        match self.block_serve_engine() {
            Some(engine) => {
                self.handle_block_request_with_credit(stream, req, engine, declared_size).await
            }
            None => {
                tracing::error!(
                    local_device_id = %self.local_device_id,
                    peer = %self.peer_device_id,
                    group_id = %req.folder_group_id,
                    "refusing a block request: this session has no BlockServeEngine installed"
                );
                self.reject_block_request(stream, "source has no serving engine installed").await
            }
        }
    }

    /// The credit-gated, coalesced block-serving path -- the only one this
    /// build has, once this session has an engine installed. Called only
    /// after `handle_block_request`'s own authorization/reference/
    /// provenance checks already passed.
    ///
    /// Admits against the block's own declared size (`declared_size`,
    /// already read by `authorize_block_serve`) when it's cheaply known
    /// from the live `FileRecord` -- the common case -- falling back to
    /// `MAX_BLOCK_SIZE` as a pessimistic worst-case reservation only when
    /// it isn't (the reference was established via native state/retained-
    /// version path instead, which exposes no size without a real read).
    /// Reserving the theoretical maximum for EVERY request regardless of
    /// real size would make a device's own advertised byte budgets
    /// massively over-conservative for the common case of many small
    /// blocks (confirmed: 72 concurrent 16 KiB requests against
    /// `MAX_BLOCK_SIZE` = 16 MiB each spuriously exhausted a 512 MiB
    /// global budget and returned `Busy` for blocks this device had
    /// trivially serviceable room for). Released once the reply has been
    /// sent (`ServeCreditGuard`'s drop).
    /// Upper bound on how long this handler waits for a fair dispatch turn
    /// before giving up and answering `Busy` instead of continuing to wait.
    /// Must stay comfortably under `FETCH_RESPONSE_TIMEOUT` (the
    /// requester's own response deadline) with enough margin left for the
    /// `Busy` reply's own network RTT to arrive before that deadline fires
    /// -- otherwise every congested request loses this race by
    /// construction: the source is still waiting in `FairDispatchQueue`
    /// when the requester has already given up and moved on, and `Busy`'s
    /// entire point (an EXPLICIT, actionable "try again shortly with this
    /// hint" versus a silent timeout) never actually gets used under the
    /// exact congestion it exists for.
    const DISPATCH_WAIT_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

    async fn handle_block_request_with_credit(
        &self,
        stream: &mut dyn crate::ports::PeerBlockStream,
        req: yadorilink_sync_wire::BlockRequestHeaderFrame,
        engine: Arc<crate::block_serve::BlockServeEngine>,
        declared_size: Option<u32>,
    ) -> Result<(), PeerSessionError> {
        // `declared_size` was already read as part of `authorize_block_
        // serve`, in the same offloaded hop as the reference/provenance
        // checks (`block_request_checks_off_runtime`) -- not a local
        // `FileRecord` lookup done here. `FairDispatchQueue` needs this
        // size up front to pick fairly by bytes granted, not request count
        // (see that queue's own doc comment); only `try_admit` below
        // actually reserves anything, so using an already-computed size
        // here does not reintroduce "credit held hostage while merely
        // waiting a turn" (see `acquire_dispatch_turn`'s own doc comment).
        let reserve_bytes = declared_size.map(u64::from).unwrap_or(MAX_BLOCK_SIZE as u64);
        // Waits for a fair turn BEFORE reserving any byte credit -- see
        // `acquire_dispatch_turn`'s own doc comment for why this ordering
        // matters: byte credit must never be held hostage while a request
        // is merely waiting its turn in the fairness queue. This is what
        // actually provides cross-peer/cross-group fairness;
        // `BlockServeCredit`'s byte budgets alone cannot (see
        // `FairDispatchQueue`'s own doc comment).
        //
        // Bounded by `DISPATCH_WAIT_BUDGET`, not awaited unboundedly: an
        // unbounded wait here defeats `Busy`'s whole purpose under the
        // congestion it exists for (see that constant's own doc comment),
        // and would let an authorized peer that floods requests pile up
        // arbitrarily many waiting tasks otherwise (mitigated further by
        // `FairDispatchQueue`'s own `max_waiting` cap, which can also
        // reject this outright with no wait at all). Dropping the timed-
        // out future here is safe regardless of whether a turn had
        // already been granted moments before the deadline -- see
        // `FairDispatchQueue::acquire`'s own doc comment.
        let dispatch_guard = match tokio::time::timeout(
            Self::DISPATCH_WAIT_BUDGET,
            engine.acquire_dispatch_turn(&self.peer_device_id, &req.folder_group_id, reserve_bytes),
        )
        .await
        {
            Ok(Ok(guard)) => guard,
            Ok(Err(busy)) => return self.respond_block_busy(stream, busy).await,
            Err(_elapsed) => {
                return self
                    .respond_block_busy(
                        stream,
                        crate::block_serve::ServeBusy {
                            retry_after_ms: Self::DISPATCH_WAIT_BUDGET.as_millis() as u32,
                            queue_depth: 0,
                        },
                    )
                    .await;
            }
        };
        let _dispatch_guard = dispatch_guard;
        // The dispatch wait above can take up to `DISPATCH_WAIT_BUDGET` --
        // long enough for a netmap update to revoke this peer's
        // authorization for this group while this request was merely
        // waiting its turn. `handle_block_request`'s own `shares_group`
        // check only covers the instant this function was first entered;
        // re-checking here, immediately after the wait and before any
        // credit is reserved or the block is actually read/sent, closes
        // the disclosure window a since-revoked peer would otherwise get
        // for up to that entire wait.
        if !self.shares_group(&req.folder_group_id) {
            tracing::warn!(
                group_id = %req.folder_group_id,
                peer = %self.peer_device_id,
                "peer's authorization for this folder group was revoked while its request \
                 waited for a dispatch turn; refusing"
            );
            return self
                .reject_block_request(stream, "requester is not authorized for this folder group")
                .await;
        }
        let credit_guard =
            match engine.try_admit(&self.peer_device_id, &req.folder_group_id, reserve_bytes) {
                Ok(guard) => guard,
                Err(busy) => return self.respond_block_busy(stream, busy).await,
            };

        // `Some(exact)` when `authorize_block_serve` found a real
        // declared size (the common case) -- the stored bytes must match
        // it EXACTLY, since a hash commits to specific bytes of a specific
        // length. `None` when this request fell back to `MAX_BLOCK_SIZE`
        // (native state/retained-version path, which exposes no exact size) --
        // there the stored bytes only need to fit under that pessimistic
        // reservation, not match it exactly.
        let expected_size = declared_size.map(u64::from);
        // `expected_size` is part of the coalescing key itself -- see
        // `coalesce_cell`'s own doc comment for why two requesters
        // disagreeing on expected size (one correctly sized, one
        // corrupted/understated) must never share a cell.
        let cell = engine.coalesce_cell(&req.folder_group_id, &req.block_hash, expected_size);
        let store = self.store.clone();
        let hash_hex = hex::encode(&req.block_hash);
        // `get_or_init` guarantees exactly one call to this closure runs
        // per still-live cell, regardless of how many concurrent
        // requesters (across every session on this device) are awaiting
        // the same `(group_id, hash)` -- every waiter beyond the first
        // gets this same result by reference (`Bytes`'s cheap refcount
        // clone), not its own copy of the read/verify/compress work.
        let result = cell
            .get_or_init(|| async move {
                let read_result = spawn_blocking(move || {
                    let _reads = yadorilink_local_storage::io_diag::attribute_reads(
                        yadorilink_local_storage::io_diag::ReadReason::PeerServe,
                    );
                    store.get(&hash_hex)
                })
                .await;
                let data = match read_result {
                    Ok(Ok(data)) => data,
                    Ok(Err(e @ yadorilink_local_storage::StorageError::NotFound(_))) => {
                        return Err(crate::block_serve::CoalesceFailure::Absent(e.to_string()))
                    }
                    Ok(Err(e)) => {
                        return Err(crate::block_serve::CoalesceFailure::ReadFailed(e.to_string()))
                    }
                    Err(join_err) => {
                        return Err(crate::block_serve::CoalesceFailure::ReadFailed(
                            join_err.to_string(),
                        ))
                    }
                };
                // Serve-boundary invariant check: the credit this request
                // reserved (`reserve_bytes`, from the `declared_size`
                // `authorize_block_serve` already read, or `MAX_BLOCK_SIZE`)
                // is only meaningful if the bytes this
                // device is ABOUT to send actually match what was
                // reserved for. `BlockStore::get` already verifies the
                // read bytes hash to the requested `block_hash` (so this
                // isn't re-checking content correctness), but nothing
                // upstream of this point cross-checks the read's LENGTH
                // against the size the referencing version declared for
                // this hash -- a corrupted/inconsistent index could
                // otherwise let a request bypass its own credit
                // reservation by referencing a hash whose real stored size
                // is larger than what was ever charged against the
                // per-peer/per-group/global budgets.
                let actual_len = data.len() as u64;
                let size_ok = match expected_size {
                    Some(expected) => actual_len == expected,
                    None => actual_len <= MAX_BLOCK_SIZE as u64,
                };
                if !size_ok {
                    return Err(crate::block_serve::CoalesceFailure::SizeMismatch(format!(
                        "stored block is {actual_len} bytes, expected {}",
                        expected_size
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| format!("<= {MAX_BLOCK_SIZE}"))
                    )));
                }
                // Always considered, never negotiated: both ends of a
                // connection are the same protocol generation, so there is
                // no peer that might not understand a compressed body.
                // `compress_block` still returns the raw bytes whenever
                // compressing them would make them larger, which is a
                // property of this payload, not of this peer.
                match spawn_blocking(move || compress_block(&data)).await {
                    Ok((data, compression)) => Ok((Bytes::from(data), compression)),
                    Err(join_err) => {
                        Err(crate::block_serve::CoalesceFailure::ReadFailed(join_err.to_string()))
                    }
                }
            })
            .await
            .clone();

        let send_result = match result {
            Ok((data, compression)) => {
                // Gate the outbound payload on the upload bucket before the
                // send proceeds -- consumes tokens for the actual bytes
                // about to be transmitted, awaiting bucket refill rather
                // than dropping.
                self.rate_limiters().upload.acquire(data.len() as u64).await;
                // The body goes onto the stream exactly as it sits in the
                // coalesced buffer: one copy into the transport, and none
                // into an intermediate encoding. `size` is what is on the
                // wire, so it is the post-compression length.
                self.respond_to_block_request(
                    stream,
                    yadorilink_sync_wire::BlockResponseOutcomeFrame::Found {
                        size: data.len() as u64,
                        hash: req.block_hash,
                        compression,
                    },
                    &data,
                )
                .await
            }
            Err(crate::block_serve::CoalesceFailure::Absent(read_error)) => {
                // Referenced and provenance-verified, but the bytes are not
                // in the store (e.g. reclaimed since): truthfully not held.
                tracing::warn!(
                    local_device_id = %self.local_device_id,
                    group_id = %req.folder_group_id,
                    path = %req.file_path,
                    hash = %hex::encode(&req.block_hash),
                    error = %read_error,
                    "a referenced, provenance-verified block is not in the block store"
                );
                self.respond_to_block_request(
                    stream,
                    yadorilink_sync_wire::BlockResponseOutcomeFrame::DontHave,
                    &[],
                )
                .await
            }
            Err(crate::block_serve::CoalesceFailure::ReadFailed(read_error)) => {
                // The bytes are there but could not be read back intact.
                // Not `DontHave`: that answer means "this device does not
                // hold the block", and a requester may conclude from it,
                // together with every other holder's, that the content no
                // longer exists anywhere. A local read failure says nothing
                // of the kind, so it is refused instead.
                tracing::warn!(
                    local_device_id = %self.local_device_id,
                    group_id = %req.folder_group_id,
                    path = %req.file_path,
                    hash = %hex::encode(&req.block_hash),
                    error = %read_error,
                    "block_store.get failed while serving a referenced, provenance-verified \
                     block request"
                );
                self.reject_block_request(stream, "stored block could not be read").await
            }
            Err(crate::block_serve::CoalesceFailure::SizeMismatch(reason)) => {
                tracing::error!(
                    local_device_id = %self.local_device_id,
                    group_id = %req.folder_group_id,
                    hash = %hex::encode(&req.block_hash),
                    reason,
                    "refusing to serve a block whose stored size does not match its declared \
                     size -- local index/store inconsistency"
                );
                self.reject_block_request(stream, &reason).await
            }
        };
        drop(credit_guard);
        send_result
    }

    /// Answers `Busy`: this device's serve queue is at its in-flight credit
    /// limit for this request right now, not permanently unable to serve it.
    async fn respond_block_busy(
        &self,
        stream: &mut dyn crate::ports::PeerBlockStream,
        busy: crate::block_serve::ServeBusy,
    ) -> Result<(), PeerSessionError> {
        self.respond_to_block_request(
            stream,
            yadorilink_sync_wire::BlockResponseOutcomeFrame::Busy {
                retry_after_ms: busy.retry_after_ms,
                queue_depth: busy.queue_depth,
            },
            &[],
        )
        .await
    }

    /// `handle_block_request` reaches this on EVERY incoming
    /// `BlockRequest` this device serves -- roughly 1500 times per GiB
    /// transferred to a single peer -- so an unguarded inline call here
    /// blocked this session's own tokio worker, including its own channel
    /// actor, on the same writer-gate contention `record_materialized_
    /// fingerprint_off_runtime`'s doc comment describes.
    /// `self.block_serve_authorizer.authorize_block_serve` (proof-carrying-
    /// change) folds
    /// the reference check, the provenance check, and the declared-size
    /// lookup into one semantic operation and one `block_in_place` hop,
    /// mirroring the receive path's own twin combination
    /// (`record_group_block_provenance` + `clear_block_fetch_refusal`
    /// behind one `spawn_blocking`, in `ensure_blocks_present`): the checks
    /// run back to back against the same connection, and the provenance
    /// check short-circuits out of the same closure once the reference
    /// check fails, skipping the extra SQLite read entirely for the common
    /// unreferenced-request case. `block_in_place` rather than
    /// `spawn_blocking`: the closure borrows `self` and `req` rather than
    /// owning them, so nothing here needs cloning just to satisfy a
    /// `'static` closure.
    ///
    /// One behavioural difference from the three separate reads this
    /// replaced: the declared-size read used to happen in a SECOND
    /// `block_in_place` hop, later, in `handle_block_request_with_credit`,
    /// just before the credit reservation. It now happens in this same
    /// earlier hop, so the reserved size can come from a marginally
    /// staler live record. The value was already treated as an estimate
    /// and is still only read for authorized requests, so this is
    /// acceptable.
    async fn block_request_checks_off_runtime(
        &self,
        req: &yadorilink_sync_wire::BlockRequestHeaderFrame,
    ) -> Result<BlockRequestCheckOutcome, PeerSessionError> {
        let check = || -> Result<BlockRequestCheckOutcome, PeerSessionError> {
            match self.block_serve_authorizer.authorize_block_serve(
                &req.folder_group_id,
                &req.file_path,
                &req.block_hash,
            )? {
                crate::ports::BlockServeAuthorization::Allowed { declared_size } => {
                    Ok(BlockRequestCheckOutcome::Ok { declared_size })
                }
                crate::ports::BlockServeAuthorization::NotReferenced => {
                    Ok(BlockRequestCheckOutcome::NotReferenced)
                }
                crate::ports::BlockServeAuthorization::NoProvenance => {
                    Ok(BlockRequestCheckOutcome::NoProvenance)
                }
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(check)
            }
            _ => check(),
        }
    }
}
