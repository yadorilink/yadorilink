//! Requester side of the block stream lane: fetching one block from this
//! peer, its timeout/retry/adaptive-window policy, and the verified
//! fetch-and-store body the convergence driver runs per block.

use bytes::Bytes;
use yadorilink_replica_domain::file::BlockInfo;

use crate::error::PeerSessionError;

use super::{
    block_data_matches, decompress_block, spawn_blocking, PeerSyncSession, MAX_BLOCK_SIZE,
    NO_VERIFIED_PROVENANCE_REASON,
};

/// `ensure_blocks_present`'s per-block concurrent-fetch result --
/// `Present` once a block is fetched, hash-verified, and locally stored
/// (or already present, though that case never reaches this far -- see
/// `ensure_blocks_present`'s own dedup check), `Missing` when every bounded
/// retry/fail-fast path in `fetch_one_block` gave up on this
/// block. Kept distinct from `FetchOutcome` (that enum is per-attempt wire
/// semantics; this one is the per-block, post-retry verdict the concurrent
/// scheduler above actually needs to make its all-present/give-up
/// decisions).
///
/// `Fetched` carries the block's bytes as well as its hash, and means
/// exactly what its name says: these bytes arrived and passed the wire
/// checks, and NOTHING has been written to the block store yet. Durability
/// is the caller's job now -- `ensure_blocks_present_core` accumulates
/// these and commits them through `BlockContentStore::put_prepared_batch`
/// in bounded batches, so one durability barrier serves many blocks
/// instead of one barrier per block.
///
/// That split is why this variant is emphatically not called `Present`: a
/// block is present only once its batch has committed, and the window
/// between `Fetched` and that commit is real. Provenance is still recorded
/// strictly after the durable write it attests to -- a hash only joins
/// `newly_fetched_hashes` once the batch carrying it has returned `Ok`
/// (those hashes are then flushed through ONE batched
/// `record_group_block_provenance` call per invocation, instead of one
/// `write_immediate` SQLite transaction per block).
pub(crate) enum BlockFetchOutcome {
    Fetched {
        hash: Vec<u8>,
        data: Bytes,
    },
    Missing,
    /// The peer answered `rejected` with `NO_VERIFIED_PROVENANCE_REASON` --
    /// see `BlockFetch::VerifiedRefusal`, which this becomes at the
    /// convergence boundary, for why this one refusal is distinguished.
    VerifiedRefusal {
        reason: String,
    },
}

#[derive(Clone, Debug)]
enum FetchOutcome {
    Found(Bytes),
    /// The peer explicitly answered that it does not hold the block.
    NotFound,
    /// The exchange ended before any answer arrived: the stream did not
    /// open, the request could not be sent, or the response or its body was
    /// cut short (e.g. the session ended). Says nothing about whether the
    /// peer holds the block; kept apart from `NotFound` so a caller that has
    /// to tell "this peer does not have it" from "this peer did not answer"
    /// can.
    Lost,
    /// A response arrived but this device could not use it (decompression
    /// failure, decompression-bomb bound exceeded, or similar) —
    /// deliberately distinct from `NotFound` (see this enum's own doc
    /// comment).
    Unusable,
    /// No reply at all arrived within `fetch_block_raw`'s own
    /// `FETCH_RESPONSE_TIMEOUT` — deliberately distinct from `NotFound`
    /// (an explicit, fast refusal): this means the request went out and
    /// nothing came back, which is a much heavier signal (a slow/
    /// unresponsive peer or connection, not a quick index-not-updated-yet
    /// race) that should fail fast rather than retry the same peer, unlike
    /// `NotFound`'s bounded same-peer retry in `ensure_blocks_present`.
    TimedOut,
    /// The peer answered with `BlockReply.Busy`: its serve queue for this
    /// block is at its in-flight credit limit right now, not permanently
    /// absent. Deliberately distinct from every other variant
    /// — a caller must not treat this as `NotFound`/`Unusable` (this peer
    /// may well have the block) nor immediately fail over to another peer
    /// the way `TimedOut` warrants (retrying the SAME peer after
    /// `retry_after_ms` is usually cheaper than reconnecting elsewhere) —
    /// see `ensure_blocks_present`'s own handling.
    Busy {
        retry_after_ms: u32,
    },
    /// The peer answered with `BlockReply.Rejected`: a hard denial (missing
    /// authorization/provenance, or a malformed request) that retrying
    /// will not resolve -- deliberately distinct from `NotFound`, which
    /// `ensure_blocks_present` retries against the same peer up to
    /// `NOT_FOUND_RETRY_ATTEMPTS` times on the theory that a "not
    /// referenced yet" race commonly clears within a second. Collapsing
    /// `Rejected` into `NotFound` (the pre-this-variant behavior) meant a
    /// permanent authorization denial got the identical bounded-retry
    /// treatment as a transient index-not-updated-yet race, needlessly
    /// re-asking a peer that will never answer differently.
    Rejected {
        reason: String,
    },
}

impl FetchOutcome {
    fn into_bytes(self) -> Option<Bytes> {
        match self {
            FetchOutcome::Found(data) => Some(data),
            FetchOutcome::NotFound
            | FetchOutcome::Lost
            | FetchOutcome::Unusable
            | FetchOutcome::TimedOut
            | FetchOutcome::Busy { .. }
            | FetchOutcome::Rejected { .. } => None,
        }
    }
}

/// What one peer said about one block, for [`PeerSyncSession::fetch_block_answer`].
#[derive(Clone, Debug)]
pub enum BlockFetchAnswer {
    /// The block's bytes, as received; the caller still verifies them
    /// against the hash it asked for.
    Found(Bytes),
    /// The peer answered that it does not hold the block.
    DontHave,
    /// No usable answer: the exchange was lost or timed out, the peer stayed
    /// busy, refused the request, or sent something unusable. Says nothing
    /// about whether the peer holds the block.
    NoAnswer,
}

/// Counts one in-flight block fetch to this peer while it lives.
///
/// The map this replaces existed to correlate a reply to its waiter, and
/// needed an RAII guard because a caller that wrapped a fetch in its own
/// timeout would drop the future without anything ever removing its entry
/// -- an unbounded leak on a long-running daemon with an unreachable peer.
/// A stream needs no such table, so what is left is only the count the
/// adaptive window reads, and the guard only has to keep it honest across a
/// cancelled fetch.
struct InFlightBlockFetchGuard<'a> {
    counter: &'a std::sync::atomic::AtomicUsize,
}

impl Drop for InFlightBlockFetchGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl PeerSyncSession {
    /// The current recommended number
    /// of concurrent in-flight `fetch_block` requests to this peer, per
    /// this session's `AdaptiveWindow` (see that module's doc comment).
    /// `yadorilink-daemon::hydration`'s multi-peer dispatcher calls this
    /// once per fetch dispatch, in place of the old fixed
    /// `PER_PEER_IN_FLIGHT_WINDOW` lane count, so a fast/healthy session
    /// gets more concurrent lanes and a slow/lossy one gets fewer — always
    /// within `[ADAPTIVE_WINDOW_MIN, MAX_IN_FLIGHT_MESSAGES_PER_PEER]`
    /// (the window's clamp). Public for the same reason
    /// `compression_negotiated` is: an observable piece of session state a
    /// caller outside this module needs to act on.
    pub fn fetch_window(&self) -> usize {
        self.adaptive_window.current()
    }

    /// Records that a `fetch_block`
    /// request to this peer went unanswered within the *caller's* own
    /// timeout — an AIMD loss/timeout signal, backing this session's
    /// adaptive window off multiplicatively (`AdaptiveWindow::on_timeout`).
    ///
    /// This can't be observed from inside `fetch_block` itself: a caller
    /// wrapping the call in `tokio::time::timeout` (as
    /// `yadorilink-daemon::hydration`'s per-block bound already does, and
    /// as `hydrate_file_with_timeout`'s whole-batch bound does indirectly)
    /// drops the `fetch_block` future — and therefore its local `rx.await`
    /// — the instant the timeout fires, the same reason `PendingBlockGuard`
    /// exists (see its doc comment) rather than `fetch_block` ever getting
    /// a chance to run its own "it never answered" branch. Callers that
    /// impose their own bound on `fetch_block` are expected to call this
    /// when that bound is exceeded, mirroring how they already reassign a
    /// timed-out block to another candidate (e.g.
    /// `BlockWorkQueue::mark_timed_out`).
    pub fn record_fetch_timeout(&self) {
        self.adaptive_window.on_timeout();
    }

    /// Decompresses `data` per its declared `compression` (off the async
    /// runtime — same reasoning as every other compress/decompress call in
    /// this module) into a `FetchOutcome::Found`, or `Unusable` on a
    /// decompression failure. Used by `handle_block_reply`
    /// (`BlockReplyFound.data`).
    async fn resolve_block_bytes(
        &self,
        block_hash: Vec<u8>,
        data: Vec<u8>,
        compression: i32,
    ) -> FetchOutcome {
        // Only route through `spawn_blocking` when there's real
        // decompression work to do. `COMPRESSION_NONE` (and any other
        // unrecognized value) is a trivial passthrough (`decompress_block`
        // itself just clones the bytes for that case) — forcing every
        // single block reply, compressed or not, through a blocking-pool
        // round trip would add real scheduling latency to what used to be
        // an immediate, synchronous fast path, for the overwhelming
        // majority of responses (an unnegotiated peer, or a block
        // `compress_block` decided wasn't worth compressing). The "off the
        // async runtime" reasoning applies to actual CPU-bound zstd work,
        // not a no-op passthrough.
        if compression != yadorilink_sync_wire::COMPRESSION_ZSTD {
            return FetchOutcome::Found(Bytes::from(data));
        }
        match spawn_blocking(move || decompress_block(&data, compression, MAX_BLOCK_SIZE)).await {
            // `Bytes::from(Vec<u8>)` reuses the existing allocation, no
            // copy. Every waiter beyond the first then gets a cheap
            // refcount `clone` of that same `Bytes` instead of its own full
            // copy of the block — unaffected by decompression happening
            // first.
            Ok(Ok(decompressed)) => FetchOutcome::Found(Bytes::from(decompressed)),
            Ok(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    hash = %hex::encode(&block_hash),
                    peer = %self.peer_device_id,
                    "rejecting block reply: failed to decompress (corrupt payload or \
                     decompression-bomb bound exceeded); treating this peer as not having the \
                     block"
                );
                FetchOutcome::Unusable
            }
            Err(_join_err) => FetchOutcome::Unusable,
        }
    }

    /// Runs one block exchange to completion on its own stream: request
    /// header out, response header in, and the body if there is one.
    ///
    /// Everything about correlating this answer to this question is the
    /// stream itself. Nothing is registered in a pending-request table,
    /// nothing has to be cleaned up if the caller walks away, and two
    /// concurrent requests for the identical hash in different groups
    /// cannot be cross-wired -- not because an id keeps them apart, but
    /// because they were never on the same channel to begin with.
    ///
    /// Every transport-level failure -- the stream not opening, the header
    /// not going out, the response not arriving, the body ending early --
    /// resolves to `Lost` rather than an error: this peer did not supply
    /// this block on this attempt, and did not say whether it holds it.
    /// Only the peer's own `DontHave` answer is `NotFound`. A response that
    /// arrived but could not be used is `Unusable`, which callers
    /// deliberately do not retry.
    async fn fetch_block_over_stream(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
    ) -> FetchOutcome {
        // The substrate's block lane -- the only source of an outbound
        // block request now (see `SessionTransports`'s own doc comment).
        let opened = self.transports.blocks.open(group_id).await;
        let mut stream = match opened {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(%error, peer = %self.peer_device_id, "could not open a block stream");
                return FetchOutcome::Lost;
            }
        };
        let header = match self.codec.encode_block_request_header(
            yadorilink_sync_wire::BlockRequestHeaderFrame {
                folder_group_id: group_id.to_string(),
                file_path: file_path.to_string(),
                block_hash: hash.to_vec(),
            },
        ) {
            Ok(header) => header,
            Err(error) => {
                // Not reachable from anything a peer sends: this encodes
                // this device's own request.
                tracing::error!(%error, "could not encode a block request header");
                return FetchOutcome::Lost;
            }
        };
        if let Err(error) = stream.send_message(&header).await {
            tracing::debug!(%error, peer = %self.peer_device_id, "block request header could not be sent");
            return FetchOutcome::Lost;
        }
        yadorilink_fs_platform::join_timeline::mark_with_peer(
            &self.local_device_id,
            group_id,
            yadorilink_fs_platform::join_timeline::Milestone::BlockRequestSent,
            &self.peer_device_id,
        );
        // Nothing else will be sent on this side, and saying so lets the
        // responder stop waiting on a direction that has nothing left in
        // it.
        stream.finish_send();

        let response = match stream
            .recv_message(yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(%error, peer = %self.peer_device_id, "block stream ended before its response header");
                return FetchOutcome::Lost;
            }
        };
        let response = match self.codec.decode_block_response_header(&response) {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(%error, peer = %self.peer_device_id, "discarding a malformed block response header");
                return FetchOutcome::Unusable;
            }
        };
        yadorilink_fs_platform::join_timeline::mark_with_peer(
            &self.local_device_id,
            group_id,
            yadorilink_fs_platform::join_timeline::Milestone::BlockResponseReceived,
            &self.peer_device_id,
        );
        use yadorilink_sync_wire::BlockResponseOutcomeFrame as Outcome;
        let (size, echoed_hash, compression) = match response.outcome {
            Outcome::Found { size, hash, compression } => (size, hash, compression),
            Outcome::DontHave => return FetchOutcome::NotFound,
            Outcome::Busy { retry_after_ms, .. } => return FetchOutcome::Busy { retry_after_ms },
            Outcome::Rejected { reason } => {
                tracing::warn!(
                    peer = %self.peer_device_id,
                    hash = %hex::encode(hash),
                    reason = %reason,
                    "block request rejected by peer"
                );
                return FetchOutcome::Rejected { reason };
            }
        };
        // The requester already knows which hash it asked for, so the
        // echoed one is a cross-check: a peer answering with a different
        // block's identity is answering a question that was not asked, and
        // its bytes are not stored on the strength of this stream having
        // been the right one.
        if echoed_hash != hash {
            tracing::warn!(
                peer = %self.peer_device_id,
                requested = %hex::encode(hash),
                answered = %hex::encode(&echoed_hash),
                "rejecting a block response bound to a different hash than the request"
            );
            return FetchOutcome::Unusable;
        }
        // Bounded before a single byte is allocated for it. The transport
        // has its own backstop, but this is the check that knows what this
        // protocol considers a legal block, and it must answer `Unusable`
        // (a response that arrived and cannot be used) rather than letting
        // the transport turn a peer's claim into an allocation.
        let Ok(size) = usize::try_from(size) else { return FetchOutcome::Unusable };
        if size > MAX_BLOCK_SIZE {
            tracing::warn!(
                peer = %self.peer_device_id,
                hash = %hex::encode(hash),
                declared = size,
                max = MAX_BLOCK_SIZE,
                "rejecting a block response declaring more bytes than any legal block"
            );
            return FetchOutcome::Unusable;
        }
        let body = match stream.recv_body(size).await {
            Ok(body) => body,
            Err(error) => {
                tracing::debug!(%error, peer = %self.peer_device_id, "block stream ended before its body");
                return FetchOutcome::Lost;
            }
        };
        // Counted here, on the bytes that actually crossed the wire, before
        // decompression or any further handling -- see
        // `content_bytes_received`'s own doc comment for why this is the
        // exact observation point.
        self.content_bytes_received
            .fetch_add(body.len() as u64, std::sync::atomic::Ordering::Relaxed);
        self.resolve_block_bytes(hash.to_vec(), body, compression).await
    }

    /// Requests a block from the peer over a stream of its own and awaits
    /// the response that arrives on it. Public: the low-level per-block fetch
    /// primitive the daemon's
    /// multi-session hydration dispatcher (`yadorilink-daemon::hydration`)
    /// calls directly across several sessions concurrently, rather than
    /// each session fetching a whole file's blocks sequentially on its
    /// own. Does not write to the block store — the caller does that with
    /// the returned data, so callers coordinating across multiple
    /// sessions decide for themselves when/whether to persist a result.
    /// Returns `Bytes`, not `Vec<u8>`: a caller that hands the block on --
    /// to local storage, or to another waiter -- pays a refcount clone
    /// rather than a copy of the whole block.
    ///
    /// This collapses `FetchOutcome::
    /// NotFound`/`Unusable`/`TimedOut`/`Redirect` into the same `None` as
    /// before this change — unchanged for this function's existing callers
    /// (the daemon's multi-peer dispatcher, which already has its own "try
    /// a different peer" fallback for any of them). `ensure_blocks_present`
    /// calls `fetch_block_raw` directly instead, to see the distinction and
    /// retry `NotFound` (which this function does not) — see that
    /// function's and `FetchOutcome`'s doc comments.
    ///
    /// `Busy` alone gets a bounded same-peer retry here (mirroring
    /// `ensure_blocks_present`'s own, with the same `BUSY_RETRY_ATTEMPTS`/
    /// `BUSY_RETRY_MAX_DELAY`), rather than collapsing straight to `None`
    /// like every other non-`Found` outcome: `FetchOutcome::Busy`'s own doc
    /// comment states a caller must not treat it as a permanent miss and
    /// fail over elsewhere the way `TimedOut` warrants, since retrying the
    /// SAME peer after its own `retry_after_ms` hint is usually cheaper —
    /// a caller that skipped this and went straight to `into_bytes` would
    /// treat ordinary, temporary dispatch-queue backpressure (see
    /// `handle_block_request_with_credit`'s `DISPATCH_WAIT_BUDGET`) as a
    /// permanent failure the single-source caller has no other peer to
    /// fall back to for.
    pub async fn fetch_block(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
    ) -> Result<Option<Bytes>, PeerSessionError> {
        self.fetch_block_with_response_timeout(
            group_id,
            file_path,
            hash,
            Self::FETCH_RESPONSE_TIMEOUT,
        )
        .await
    }

    /// Like [`Self::fetch_block`], but sizes the per-attempt response
    /// deadline to `expected_size` via [`Self::fetch_response_timeout_
    /// for`] instead of the fixed [`Self::FETCH_RESPONSE_TIMEOUT`] baseline
    /// -- see that function's own doc comment for why a single fixed
    /// deadline undercounts a block-fetch sharing a relay-forwarded
    /// connection with several concurrent siblings. Callers that know the
    /// block's declared size in advance (`yadorilink-daemon::hydration`'s
    /// multi-peer dispatcher, from the `FileRecord`'s own `BlockInfo`)
    /// should prefer this over `fetch_block`.
    pub async fn fetch_block_sized(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
        expected_size: u64,
    ) -> Result<Option<Bytes>, PeerSessionError> {
        self.fetch_block_with_response_timeout(
            group_id,
            file_path,
            hash,
            Self::fetch_response_timeout_for(expected_size),
        )
        .await
    }

    async fn fetch_block_with_response_timeout(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
        response_timeout: std::time::Duration,
    ) -> Result<Option<Bytes>, PeerSessionError> {
        Ok(self
            .fetch_block_outcome(group_id, file_path, hash, response_timeout)
            .await?
            .into_bytes())
    }

    /// Like [`Self::fetch_block_sized`], but keeps the peer's explicit
    /// "I do not hold this block" apart from every other way the attempt
    /// can come back empty-handed. A caller that must never mistake an
    /// unanswered request for missing content (one that reports content as
    /// unobtainable only when every peer that could hold it said so) needs
    /// that distinction; every other caller wants [`Self::fetch_block_sized`].
    pub async fn fetch_block_answer(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
        expected_size: u64,
    ) -> Result<BlockFetchAnswer, PeerSessionError> {
        let outcome = self
            .fetch_block_outcome(
                group_id,
                file_path,
                hash,
                Self::fetch_response_timeout_for(expected_size),
            )
            .await?;
        Ok(match outcome {
            FetchOutcome::Found(data) => BlockFetchAnswer::Found(data),
            FetchOutcome::NotFound => BlockFetchAnswer::DontHave,
            FetchOutcome::Lost
            | FetchOutcome::Unusable
            | FetchOutcome::TimedOut
            | FetchOutcome::Busy { .. }
            | FetchOutcome::Rejected { .. } => BlockFetchAnswer::NoAnswer,
        })
    }

    /// One block request with the bounded same-peer `Busy` retry described
    /// on [`Self::fetch_block`].
    async fn fetch_block_outcome(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
        response_timeout: std::time::Duration,
    ) -> Result<FetchOutcome, PeerSessionError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.fetch_block_raw(group_id, file_path, hash, response_timeout).await? {
                FetchOutcome::Busy { retry_after_ms } if attempt < Self::BUSY_RETRY_ATTEMPTS => {
                    let delay = std::time::Duration::from_millis(retry_after_ms.into())
                        .min(Self::BUSY_RETRY_MAX_DELAY);
                    tokio::time::sleep(delay).await;
                }
                outcome => return Ok(outcome),
            }
        }
    }

    /// How long `fetch_block_raw` waits for *any* reply (found, not-found,
    /// or unusable) to one `BlockRequest` before giving up on this attempt
    /// entirely. Without this, a peer that never replies at all (as
    /// opposed to replying `not_found`) left `rx.await` unbounded here,
    /// relying entirely on whichever *external* timeout a caller happened
    /// to wrap the whole call in -- `ensure_blocks_present` has no such
    /// per-request wrap, only `materialize_dag_content_head`'s
    /// whole-batch `DEFAULT_HYDRATION_TIMEOUT` (30s) around the *entire*
    /// `ensure_blocks_present` call. A confirmed, reproduced regression
    /// (reproduced): the
    /// Convergence Engine's own concurrent audit calls measurably hit this
    /// exact 30s ceiling on individual attempts, and with up to
    /// `MAX_PEERS_PER_TICK` (2) candidates tried sequentially per tick,
    /// a single `process_group` call was measured taking over 60s --
    /// comfortably enough, across just two such ticks, to trip a 90s
    /// stall detector even before considering any other cause. Matches
    /// `yadorilink-daemon::hydration`'s own `PER_BLOCK_FETCH_TIMEOUT`
    /// (5s) -- the value this codebase already considers reasonable for
    /// one block's own round trip, independent of this being a different
    /// crate/caller.
    pub(crate) const FETCH_RESPONSE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(5);

    /// Conservative sustained per-request throughput assumed when sizing a
    /// block-fetch deadline via [`Self::fetch_response_timeout_for`] --
    /// deliberately far below this session's own configured rate-limiter
    /// caps, because a request sharing one relay-forwarded connection with
    /// several concurrent siblings measurably does not get anywhere near
    /// the connection's full nominal bandwidth to itself.
    ///
    /// Measured directly, not guessed: `topology_relay_post_recovery_
    /// block_fetch_diagnostic.rs`'s case E found 8 concurrent 128KiB block
    /// fetches sharing one post-recovery relay session all needed 13.3-
    /// 14.3s to complete once actually given room to (raised `FETCH_
    /// RESPONSE_TIMEOUT` to 20s to observe this; all 8 succeeded, none
    /// hung) -- effective per-request throughput under that contention was
    /// ~9-10 KiB/s, nowhere near this session's nominal rate-limiter caps.
    /// A single lane through the SAME relay session, and 8 concurrent
    /// lanes direct to a non-relayed peer, both completed in well under a
    /// second -- so this is a real, reproducible property of several
    /// concurrent lanes sharing one relay-forwarded connection, not a
    /// structural transport bug (nothing upstream of this deadline was
    /// found dropping packets: `RelayForwarder`'s own recv loop, this
    /// device's outbound control-channel queue, and the QUIC stack's own
    /// inbound datagram queue were all instrumented and showed zero drops during
    /// the failing runs). The fixed 5s `FETCH_RESPONSE_TIMEOUT` alone was
    /// silently aborting (not just timing out but resetting) genuinely
    /// still-progressing fetches before they could finish. Set below the
    /// measured floor for real margin, not tuned to just barely pass it.
    const FETCH_RESPONSE_CONSERVATIVE_THROUGHPUT_BYTES_PER_SEC: u64 = 8 * 1024;

    /// The per-attempt response deadline a block-fetch of `expected_size`
    /// bytes should use: [`Self::FETCH_RESPONSE_TIMEOUT`]'s own fixed
    /// baseline (still what bounds how quickly a genuinely unresponsive
    /// peer is detected for a negligibly-sized request) plus a top-up
    /// proportional to size at [`Self::FETCH_RESPONSE_CONSERVATIVE_
    /// THROUGHPUT_BYTES_PER_SEC`] -- see that constant's own doc comment
    /// for the measurement behind it. `pub` so callers outside this crate
    /// (`yadorilink-daemon::hydration`'s multi-peer dispatcher, whose own
    /// outer per-block wrap must stay strictly above whatever this
    /// returns, or it would preempt this deadline before it ever has a
    /// chance to fire on its own) can size their own wrapping timeout from
    /// the exact same figure instead of duplicating the formula.
    pub fn fetch_response_timeout_for(expected_size: u64) -> std::time::Duration {
        Self::FETCH_RESPONSE_TIMEOUT
            + std::time::Duration::from_secs_f64(
                expected_size as f64
                    / Self::FETCH_RESPONSE_CONSERVATIVE_THROUGHPUT_BYTES_PER_SEC as f64,
            )
    }

    /// Counts one in-flight block fetch to this peer for as long as the
    /// returned guard lives, and reports how many are outstanding
    /// immediately after this one starts (so it counts itself: `1` means
    /// this fetch has no live sibling yet).
    ///
    /// `fetch_block_raw` needs that number at the exact moment the request
    /// goes out, to tell `AdaptiveWindow::on_success` whether the round trip
    /// it measures is trustworthy evidence of this link's real RTT. See
    /// that function's own doc comment for why a live sibling at send time
    /// makes that not so: the peer's answers need not come back in the order
    /// its questions were asked once more than one is outstanding, so a
    /// queued answer's latency reflects its siblings' service time in an
    /// order this session cannot recover after the fact, not just its own
    /// real round trip.
    fn begin_block_fetch(&self) -> (InFlightBlockFetchGuard<'_>, usize) {
        let in_flight_after_registering =
            self.in_flight_block_fetches.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        (
            InFlightBlockFetchGuard { counter: &self.in_flight_block_fetches },
            in_flight_after_registering,
        )
    }

    async fn fetch_block_raw(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
        response_timeout: std::time::Duration,
    ) -> Result<FetchOutcome, PeerSessionError> {
        let (_in_flight_guard, in_flight_at_send) = self.begin_block_fetch();
        // Measured from just before
        // the request goes out to the response actually arriving — the
        // real block-request-to-response round trip the adaptive
        // window is driven by. `in_flight_at_send` (this request included)
        // is captured before the request is even on the wire, so it
        // reflects this request's own queue position, not whatever has
        // resolved by the time the answer comes back.
        let started_at = std::time::Instant::now();
        // A real timeout (nothing back within `response_timeout`) IS fed to
        // the adaptive window here, directly — unlike the external-timeout
        // case `record_fetch_timeout`'s own doc comment describes (a
        // caller's own wrap drops this future before it ever gets a chance
        // to observe anything), this timeout fires *inside*
        // `fetch_block_raw` itself, so it can record the signal immediately
        // rather than relying on a caller to notice and call back in.
        //
        // Dropping the exchange future on timeout is what abandons the
        // stream, which resets it -- so a responder still working on a
        // request nobody is waiting for learns that from the transport
        // rather than finishing the read and writing into nothing.
        let result = match tokio::time::timeout(
            response_timeout,
            self.fetch_block_over_stream(group_id, file_path, hash),
        )
        .await
        {
            Ok(payload) => {
                // `Busy` in particular must NEVER reach `on_success`: the
                // peer answered quickly, but explicitly said it could NOT
                // serve this request right now -- a fast `Busy` reply is
                // not evidence the link/peer can sustain more concurrent
                // requests, it's the opposite (see `on_congestion`'s own
                // doc comment for the runaway-growth this would otherwise
                // cause). `NotFound`/`Unusable`/`Rejected` are
                // all real, prompt answers too, just not ones that say
                // anything about whether MORE concurrent requests would be
                // sustainable, so none of them feed the window either way.
                match &payload {
                    FetchOutcome::Found(_) => {
                        self.adaptive_window.on_success(started_at.elapsed(), in_flight_at_send)
                    }
                    FetchOutcome::Busy { .. } => self.adaptive_window.on_congestion(),
                    FetchOutcome::NotFound
                    | FetchOutcome::Lost
                    | FetchOutcome::Unusable
                    | FetchOutcome::Rejected { .. }
                    | FetchOutcome::TimedOut => {}
                }
                payload
            }
            Err(_elapsed) => {
                self.adaptive_window.on_timeout();
                FetchOutcome::TimedOut
            }
        };
        // Gate the received block
        // *payload* on the download bucket. The bytes have already crossed
        // the wire by this point (gating happens at the session/
        // transfer layer, not the transport itself — this can't literally
        // delay wire bytes without deep transport hooks), but debiting here
        // throttles the *pace* of subsequent fetches: every caller of this
        // function — `ensure_blocks_present`'s eager-fetch loop below, and
        // the daemon's multi-peer hydration dispatcher, which calls this
        // directly as its single per-block choke point ("one
        // global ceiling") — awaits this call before issuing its next
        // request, so a saturated download bucket naturally caps aggregate
        // throughput across every concurrent peer/lane sharing it. Neither
        // a not-found nor an unusable-payload result carries billable
        // bytes (`acquire(0)` is a no-op), so neither is ever delayed here.
        if let FetchOutcome::Found(data) = &result {
            self.rate_limiters().download.acquire(data.len() as u64).await;
        }
        Ok(result)
    }

    /// Bounded retry for a "peer did
    /// not supply a usable block" response inside `ensure_blocks_present`
    /// (not inside `fetch_block` itself, and not with a finer-grained
    /// retry-reason taxonomy — see that function's doc comment for both
    /// of those decisions). 5 total attempts (1 initial + 4 retries),
    /// ~100ms apart with jitter to avoid synchronized retry bursts when
    /// many files conflict at once, is generous enough to absorb the
    /// observed race (which resolves once the other side's own
    /// materialize/upsert completes, observed well under a second even on
    /// a resource-constrained real machine) while keeping a genuinely-
    /// unusable block's added worst-case latency small (well under 1s).
    pub const NOT_FOUND_RETRY_ATTEMPTS: u32 = 5;

    const NOT_FOUND_RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

    const NOT_FOUND_RETRY_JITTER_FRACTION: f64 = 0.25;

    pub fn not_found_retry_delay() -> std::time::Duration {
        let jitter = rand::random_range(
            -Self::NOT_FOUND_RETRY_JITTER_FRACTION..=Self::NOT_FOUND_RETRY_JITTER_FRACTION,
        );
        Self::NOT_FOUND_RETRY_BASE_DELAY.mul_f64(1.0 + jitter)
    }

    /// Bound on how many times a `BlockReply.Busy` answer is retried against
    /// the SAME peer before giving up on it, mirroring `NOT_FOUND_RETRY_
    /// ATTEMPTS`'s reasoning: `Busy` means this peer plausibly has the
    /// block but is temporarily over its own serve-credit limit, which
    /// (unlike `NotFound`'s index-not-updated-yet race) can legitimately
    /// take longer than a fixed short delay to clear, so each wait honors
    /// the peer's own `retry_after_ms` hint rather than a fixed backoff —
    /// but the retry itself is still bounded, since a persistently
    /// overloaded peer should eventually hand off to the caller's own
    /// peer-rotation rather than retry forever.
    const BUSY_RETRY_ATTEMPTS: u32 = 5;

    /// Upper bound on how long a single `Busy` wait is trusted for, so a
    /// misbehaving or malicious peer cannot stall a fetch indefinitely by
    /// advertising an enormous `retry_after_ms`.
    const BUSY_RETRY_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

    /// Fetches, hash-verifies, and locally stores exactly one block --
    /// `ensure_blocks_present`'s own per-block body, factored out
    /// unchanged so its bounded-retry/fail-fast/durability-recording logic
    /// can run concurrently for several blocks at once instead of only ever
    /// one at a time.
    pub(super) async fn fetch_one_block(
        &self,
        group_id: &str,
        file_path: &str,
        block: &BlockInfo,
        block_response_timeout: std::time::Duration,
        wire_wait: &mut std::time::Duration,
    ) -> Result<BlockFetchOutcome, PeerSessionError> {
        let mut attempt = 0;
        // Set when the peer's refusal is the one that means something --
        // see `BlockFetch::VerifiedRefusal`. Carried out of the loop rather
        // than acted on inside it: the loop's job is to decide whether the
        // block arrived.
        let mut verified_refusal: Option<String> = None;
        let fetched = loop {
            attempt += 1;
            let fetch_started = std::time::Instant::now();
            let outcome = self
                .fetch_block_raw(group_id, file_path, &block.hash, block_response_timeout)
                .await?;
            // Summed across every attempt for this one block: a retried
            // block legitimately spent that much wall-clock time waiting
            // on the wire. Reported back to the caller, which decides
            // whether to attribute it anywhere.
            *wire_wait += fetch_started.elapsed();
            tracing::debug!(
                local_device_id = %self.local_device_id,
                candidate_peer_id = %self.peer_device_id,
                file_path,
                hash = %hex::encode(&block.hash),
                attempt,
                outcome = ?outcome,
                "block fetch attempt"
            );
            match outcome {
                FetchOutcome::Found(data) => break Some(data),
                FetchOutcome::NotFound | FetchOutcome::Lost
                    if attempt < Self::NOT_FOUND_RETRY_ATTEMPTS =>
                {
                    tokio::time::sleep(Self::not_found_retry_delay()).await;
                }
                // `TimedOut` is deliberately NOT retried here, unlike
                // `NotFound`: a bounded same-peer retry makes sense for
                // a fast index-not-updated-yet race (resolves in well
                // under a second), but a peer that already didn't
                // reply within `FETCH_RESPONSE_TIMEOUT` once is a much
                // heavier signal (a slow/unresponsive connection, not
                // a quick race) -- retrying it here would just burn
                // another `FETCH_RESPONSE_TIMEOUT` for likely the same
                // outcome. Fail fast instead and let the caller's own
                // peer-rotation (the Convergence Engine tries a
                // different candidate session on its next attempt)
                // handle it.
                FetchOutcome::Busy { retry_after_ms } if attempt < Self::BUSY_RETRY_ATTEMPTS => {
                    let delay = std::time::Duration::from_millis(retry_after_ms.into())
                        .min(Self::BUSY_RETRY_MAX_DELAY);
                    tokio::time::sleep(delay).await;
                }
                // A hard denial (missing authorization/provenance, or a
                // malformed request) -- retrying this same peer will
                // not resolve it, unlike `NotFound`'s racy "not
                // referenced yet" case just above. Fail fast rather
                // than burning `NOT_FOUND_RETRY_ATTEMPTS`-worth of
                // pointless re-asks against a peer that will answer
                // identically every time.
                FetchOutcome::Rejected { ref reason } => {
                    tracing::debug!(
                        local_device_id = %self.local_device_id,
                        candidate_peer_id = %self.peer_device_id,
                        file_path,
                        hash = %hex::encode(&block.hash),
                        reason,
                        "peer rejected this block request; not retrying"
                    );
                    // This EXPLICIT, definitive refusal is
                    // durable evidence -- but ONLY when `reason` is
                    // specifically `NO_VERIFIED_PROVENANCE_REASON`. Every
                    // other `Rejected` reason (unauthorized, malformed
                    // request, size mismatch) is a real denial but proves
                    // nothing about whether the peer actually holds this
                    // version's bytes, so treating it as evidence would let
                    // e.g. an authorization failure be misread as "content
                    // unobtainable". See `DurabilityFacts::known_
                    // unobtainable_required_content`'s own doc comment for
                    // why this (not a transient NotFound/TimedOut/Busy
                    // miss, and not any other rejection reason) is the
                    // evidence that fact needs, and `block_fetch_refusals`'s
                    // schema doc for why it is bound to the exact current
                    // version, not just the path.
                    //
                    // Reported, not written down. Persisting it needs this
                    // device's durable state, which belongs to the
                    // convergence executor -- see
                    // `BlockFetch::VerifiedRefusal`.
                    if reason == NO_VERIFIED_PROVENANCE_REASON {
                        verified_refusal = Some(reason.clone());
                    }
                    break None;
                }
                FetchOutcome::NotFound
                | FetchOutcome::Lost
                | FetchOutcome::Unusable
                | FetchOutcome::TimedOut
                | FetchOutcome::Busy { .. } => break None,
            }
        };
        match fetched {
            Some(data) => {
                if !block_data_matches(block, &data) {
                    tracing::warn!(
                        file_path,
                        hash = %hex::encode(&block.hash),
                        peer = %self.peer_device_id,
                        "peer returned block data that did not match the expected hash/size"
                    );
                    return Ok(BlockFetchOutcome::Missing);
                }
                // Durability is deliberately NOT done here any more. This
                // function used to `spawn_blocking(store.put(&data))` per
                // block, which made every single block its own durability
                // barrier: a 100,000-block receive cost 100,000 fsync+index
                // commits no matter how many fetches ran concurrently.
                // Returning the bytes instead lets
                // `ensure_blocks_present_core` accumulate them and commit
                // many at once through `put_prepared_batch`, so barrier
                // count tracks GROUPS rather than blocks.
                //
                // The per-block `clear_block_fetch_refusal` moved with it,
                // and that was pure waste: its key is `(group, path,
                // version, peer)` with no hash in it, so every block of one
                // file issued the byte-for-byte identical SQLite write. It
                // now runs once per committed batch (see
                // `commit_fetched_batch`), which is idempotent-equivalent.
                //
                // What has NOT moved is the ordering contract: provenance
                // is still recorded strictly after the durable write it
                // attests to, because a hash only reaches
                // `newly_fetched_hashes` once its batch returned `Ok`.
                // Handed back un-stored; the caller batches the
                // durability commit. `call_timer`'s `add_store_put` is
                // recorded per COMMITTED BATCH now rather than per block --
                // see `commit_fetched_batch`.
                Ok(BlockFetchOutcome::Fetched { hash: block.hash.clone(), data })
            }
            None => {
                if let Some(reason) = verified_refusal {
                    return Ok(BlockFetchOutcome::VerifiedRefusal { reason });
                }
                tracing::warn!(
                    local_device_id = %self.local_device_id,
                    candidate_peer_id = %self.peer_device_id,
                    file_path,
                    hash = %hex::encode(&block.hash),
                    attempts = attempt,
                    "peer reported block as not_found after retrying; sync incomplete for this file"
                );
                Ok(BlockFetchOutcome::Missing)
            }
        }
    }
}
