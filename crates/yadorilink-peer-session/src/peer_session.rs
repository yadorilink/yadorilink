//! The per-peer transport session: exchanges content blocks and service
//! requests directly with one peer device over that peer's stream lanes
//! (`SessionTransports`), with no central server involved. One
//! `PeerSyncSession` per connected peer (a peer being offline only affects its
//! own session, never blocks sync with other reachable peers). Metadata
//! convergence is not carried here: signed deltas travel on the native
//! replication lane, and this session moves the blocks those deltas' versions
//! name (fetch for hydration and repair, serve to authorized peers) plus the
//! service RPCs.
//!
//! ## Trust boundary: an authorized peer is not necessarily benign
//!
//! Every function in this module that handles data from the peer treats the
//! connected peer as **authorized but untrusted**: it has passed
//! coordination-plane auth and its blocks pass the hash+size check
//! (`block_data_matches`), but its *choices* -- which blocks it asks for,
//! what path it names -- are adversarial input, not trusted metadata. A
//! request is served only for a block the requested file's live record or a
//! live native head of an authorized group references, and `materialize`/`hydrate_file_with_timeout`
//! re-verify the resolved write target stays under the sync root. Causal
//! ordering is carried by native provenance, never by a peer-asserted
//! counter or wall clock.

use std::future::Future;
use std::io::Read as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};

use sha2::{Digest, Sha256};

use crate::adaptive_window::AdaptiveWindow;
use crate::error::PeerSessionError;
use crate::rate_limiter::RateLimiters;
use yadorilink_replica_domain::file::BlockInfo;

mod block_fetch;
mod block_serving;
mod deps;
mod service;

pub use self::block_fetch::BlockFetchAnswer;
use self::block_fetch::BlockFetchOutcome;
pub use self::deps::{
    BlockWriteActivityProvider, CustodyRehomeResponder, HandoffLeaseResponder,
    HandoffTicketResponder, PeerHandoffLeaseGrant, PeerHandoffTicketGrant, PeerSyncSessionDeps,
    PendingLocalChangeFlush, PendingLocalFlushOutcome, RootCommitAuthorityProvider,
};

const MAX_BLOCK_SIZE: usize = yadorilink_replica_domain::limits::MAX_BLOCK_SIZE_BYTES as usize;

/// (see `run`'s recv loop, where this actually gates
/// concurrently-spawned inbound message handlers): the fixed, non-adaptive
/// per-peer concurrency ceiling. `AdaptiveWindow`'s `max` is constructed
/// to never exceed this — the
/// adaptive in-flight fetch window (`adaptive_window` field below) grows
/// and shrinks freely below it, but this remains the hard upper bound
/// nothing in this module can adapt past, so the new controller composes
/// with (rather than reintroduces a way around) the existing DoS bound.
/// The largest service RPC message this session will read. Deliberately
/// modest: everything on the service lane is control metadata, and a payload
/// approaching this is a sign something bulk has been misclassified onto it.
const SERVICE_RPC_MAX_BYTES: usize = 1 << 20;

/// How long one outgoing service RPC (open, request, single answer) may take
/// before it is abandoned as unanswered. Every service RPC fails closed on no
/// answer, so a peer that accepts the stream and never replies costs the caller
/// this long, not forever.
const SERVICE_RPC_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

const MAX_IN_FLIGHT_MESSAGES_PER_PEER: usize = 64;

// `BlockRequest` deliberately shares neither this semaphore nor a FIFO
// permit pool of its own for its actual SERVICE: it is spawned immediately
// on arrival (see `run`'s recv loop, the `Payload::BlockRequest` arm's own
// doc comment) rather than queued behind a local permit pool, for two
// reasons in combination -- (1) a `BlockRequest` handler can
// genuinely block for a long time (`handle_block_request_with_
// credit` awaits a possibly-gated disk read), and a local permit pool
// shared with control/metadata messages would let a flood of those starve
// this session's control traffic; (2) real concurrency control and
// cross-peer/cross-group fairness both live in the shared
// `BlockServeEngine` (`acquire_dispatch_turn`) now, which every session
// funnels into -- a FIFO-by-arrival PER-SESSION QUEUE here would just
// reintroduce a second, uncoordinated head-of-line-blocking point in front
// of that device-wide fairness (confirmed, reproduced:
// `stage2_block_serve_contract.rs`'s
// `late_small_requests_from_another_peer_and_group_cut_ahead_of_a_large_
// backlog` and `stalled_content_requests_do_not_delay_control_messages_
// on_the_same_session`).
//
// `BlockServeEngine::try_begin_examination` (below) is a DIFFERENT thing
// and does not reintroduce that problem: it is a non-blocking (`try_
// acquire`, never queues) cap on EXAMINATION only -- the authorization/
// reference/provenance checks that run before a request ever reaches
// `acquire_dispatch_turn` -- released the moment those checks finish,
// before dispatch/service begins, not held for the request's whole
// service. See that method's own doc for the full rationale. The cap is
// device-wide: it has no notion of which peer is consuming the budget, so
// its fairness guarantee comes from the fair dispatch queue, not from a
// per-peer examination quota.

/// The adaptive window's starting
/// point for a fresh session — matches the pre-adaptive fixed lane count
/// `yadorilink-daemon::hydration`'s multi-peer dispatcher used
/// unconditionally before this change (`PER_PEER_IN_FLIGHT_WINDOW`), so
/// day-one throughput for an as-yet-unobserved peer is unchanged; the
/// window only diverges once real RTT/timeout signals arrive on this
/// session.
const ADAPTIVE_WINDOW_INITIAL: usize = 4;

/// The adaptive window's floor —
/// even a badly degraded peer keeps at least one in-flight `fetch_block`
/// slot, rather than being starved to zero (which would need a separate
/// "peer is unusable, stop trying" decision this controller doesn't make).
const ADAPTIVE_WINDOW_MIN: usize = 1;

/// zstd's low/fast compression level, used for
/// every trial/send compression pass in this module (block payloads and
/// index-exchange payloads alike) — chosen because the compression pass
/// runs synchronously in the send path (albeit off the async runtime, via
/// `spawn_blocking`) for every candidate payload and must not become the
/// sync engine's bottleneck.
const COMPRESSION_LEVEL: i32 = 3;

/// The sender always performs one low-level (`COMPRESSION_
/// LEVEL`) trial compression pass on a candidate payload, then keeps the
/// compressed form only if it beats this fraction of the raw size — a
/// "try-compress-and-compare" heuristic, not a separate entropy-sampling
/// pre-pass. This deliberately rejects that alternative (sampling first): it
/// would add a second full pass over the data for marginal savings over
/// just running the cheap level-3 pass once and checking the result size.
/// Already-compressed/incompressible content (media, archives, encrypted
/// files) naturally fails this check and is sent raw, at the cost of one
/// cheap compression attempt — never a second, wasted full-ratio pass.
const COMPRESSION_SKIP_THRESHOLD: f64 = 0.95;

/// Compresses `data` at `COMPRESSION_
/// LEVEL` and keeps the compressed form only when it beats `COMPRESSION_
/// SKIP_THRESHOLD` of the raw size — otherwise (including on an
/// encoder error, or empty input, both treated as "not worth compressing"
/// rather than propagated, since sending raw bytes is always a safe
/// fallback) returns the original bytes tagged `Compression::None`. Pure
/// and synchronous — real CPU work for a multi-hundred-KB block, so every
/// caller in this module runs it inside `tokio::task::spawn_blocking`,
/// alongside the existing block-store I/O (same reasoning),
/// never directly on an async runtime worker thread.
fn compress_block(data: &[u8]) -> (Vec<u8>, i32) {
    if data.is_empty() {
        return (Vec::new(), yadorilink_sync_wire::COMPRESSION_NONE);
    }
    match zstd::stream::encode_all(data, COMPRESSION_LEVEL) {
        Ok(compressed)
            if (compressed.len() as f64) < (data.len() as f64) * COMPRESSION_SKIP_THRESHOLD =>
        {
            (compressed, yadorilink_sync_wire::COMPRESSION_ZSTD)
        }
        _ => (data.to_vec(), yadorilink_sync_wire::COMPRESSION_NONE),
    }
}

/// A decompression-bomb
/// bound: decompresses `data` per `declared_compression`, never
/// materializing more than `max_size + 1` bytes regardless of what the
/// compressed payload claims to expand to. This reads through a
/// `Read::take`-limited streaming decoder rather than an unbounded
/// `decode_all`-style call, so a hostile payload can't force this device
/// to allocate memory proportional to its *claimed* decompressed size
/// before this function gets a chance to reject it — the cap is enforced
/// during decompression, not after the fact on an already-materialized
/// buffer.
///
/// Callers treat an `Err` here the same way `ensure_blocks_present`
/// already treats a hash/size mismatch (`block_data_matches` returning
/// false) or a rejected index message: logged, the payload discarded, no
/// partial use of it — see `PeerSyncSession::fetch_block_over_stream`'s own
/// doc comment for the reject-and-reassign path this reuses.
fn decompress_block(
    data: &[u8],
    declared_compression: i32,
    max_size: usize,
) -> Result<Vec<u8>, PeerSessionError> {
    match declared_compression {
        yadorilink_sync_wire::COMPRESSION_ZSTD => {
            let decoder = zstd::stream::read::Decoder::new(data).map_err(PeerSessionError::Io)?;
            let mut limited = decoder.take(max_size as u64 + 1);
            let mut out = Vec::new();
            limited.read_to_end(&mut out).map_err(PeerSessionError::Io)?;
            if out.len() > max_size {
                return Err(PeerSessionError::from(std::io::Error::other(format!(
                    "decompressed payload exceeds the {max_size}-byte maximum \
                     (decompression-bomb guard)"
                ))));
            }
            Ok(out)
        }
        // Unrecognized values are treated the same as `COMPRESSION_NONE` --
        // a trivial passthrough, never a hard error (matches the previous
        // `Compression::try_from(..).unwrap_or(Compression::None)` fallback).
        _ => Ok(data.to_vec()),
    }
}

/// Default bounded concurrency for `ensure_blocks_present`'s
/// per-block fetch loop, overridable via `YADORILINK_BLOCK_FETCH_
/// CONCURRENCY` for measurement sweeps (see [`block_fetch_concurrency`]'s
/// own doc comment). 32 blocks in flight at
/// `DEFAULT_BLOCK_SIZE` (128 KiB) is ~4 MiB of concurrent in-flight
/// content -- comfortably bounded, not chosen to be optimal on its own.
pub const DEFAULT_BLOCK_FETCH_CONCURRENCY: usize = 32;

/// `YADORILINK_BLOCK_FETCH_CONCURRENCY` env override for
/// `ensure_blocks_present`'s bounded concurrent block-fetch window --
/// read fresh on every call (cheap, not on any hot per-block path) so
/// a benchmark sweep can vary it run-to-run with no rebuild. Invalid
/// or absent falls back to `DEFAULT_BLOCK_FETCH_CONCURRENCY`. Follows
/// this codebase's existing `YADORILINK_*` runtime-override convention
/// (e.g. `device_config.rs`'s `YADORILINK_CONFIG_DIR`).
pub fn block_fetch_concurrency() -> usize {
    std::env::var("YADORILINK_BLOCK_FETCH_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(DEFAULT_BLOCK_FETCH_CONCURRENCY)
}

/// The exact `Rejected` reason `send_block_request_rejected` sends when a
/// peer has no verified group provenance for a block -- the ONLY rejection
/// reason `ensure_blocks_present` treats as evidence a peer positively does
/// not hold a version's content (see `block_fetch_refusals`'s own schema
/// doc comment). Every other `Rejected` reason (unauthorized, malformed
/// request, size mismatch) is a real hard denial but proves nothing about
/// content possession, so it must never be recorded as unobtainability
/// evidence. Shared as one constant, not duplicated string literals, so the
/// emit site and the check site can never silently drift apart.
const NO_VERIFIED_PROVENANCE_REASON: &str = "no verified group provenance for this block";

/// A simulated run keeps its own timeline, but a real filesystem's `mtime`
/// is stamped by the kernel at write time, and `SystemTime::now` reads the
/// host's wall clock. Tie-breaks that compare the two (`clamp_future_mtime`/
/// `a_is_loser` in `conflict.rs`) then depend on how fast the host happened
/// to run, which turns otherwise-tiny scheduling jitter (e.g. the r2d2
/// SQLite connection pool's background thread, which runs on a real,
/// non-deterministically-scheduled OS thread) into a visibly different
/// tie-break outcome across replays of the *same* seed. This override lets a
/// DST harness put `now_unix_nanos` on the *same* synthetic timeline it also
/// stamps onto its own written files' mtimes, closing that replay
/// non-determinism. Unset in
/// production and in any test that never calls `set_test_clock_override`
/// — `now_unix_nanos` then falls through to the real `SystemTime::now`
/// exactly as before this existed.
#[cfg(turmoil)]
static DETERMINISTIC_CLOCK_OVERRIDE: std::sync::OnceLock<std::sync::atomic::AtomicI64> =
    std::sync::OnceLock::new();

/// Test-only: pins `now_unix_nanos` (every call site, process-wide) to
/// `nanos` until the next call. Safe as a single un-scoped override only
/// because of this crate's own DST convention: one network-touching
/// `#[test]` fn per binary, seeds run
/// strictly sequentially within it — never two scenarios' clocks racing
/// in the same process.
#[cfg(turmoil)]
pub fn set_test_clock_override(nanos: i64) {
    DETERMINISTIC_CLOCK_OVERRIDE
        .get_or_init(|| std::sync::atomic::AtomicI64::new(nanos))
        .store(nanos, std::sync::atomic::Ordering::SeqCst);
}

/// What [`spawn_blocking`] hands back: a real `JoinHandle` in production,
/// an already-ready future under the simulator. Both await to
/// `Result<R, JoinError>`, so only the name of the type differs.
#[cfg(not(turmoil))]
pub(crate) type BlockingHandle<R> = tokio::task::JoinHandle<R>;
#[cfg(turmoil)]
pub(crate) type BlockingHandle<R> = std::future::Ready<Result<R, tokio::task::JoinError>>;

#[cfg(not(turmoil))]
pub(crate) fn spawn_blocking<F, R>(f: F) -> BlockingHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
}

/// Under the deterministic simulator `spawn_blocking` would run `f` on a
/// real, non-simulated OS thread pool whose completion time bleeds into the
/// virtual clock non-deterministically. Running the identical work inline and
/// handing back an already-ready future drives the exact same result while
/// keeping every `spawn_blocking(...).await` call site below scheduled
/// deterministically. Every site awaits the handle immediately, so eager
/// inline execution is behavior-preserving; the `Ok`-wrapped
/// `Result<R, JoinError>` matches the await output shape the production
/// `JoinHandle` yields, so no call site needs to change.
///
/// One site does hold the handle rather than awaiting it at once
/// (`spawn_commit`, whose handles queue in a `FuturesUnordered`). Under
/// simulation that batch's work therefore happens eagerly, at the point
/// the handle is created rather than where it is awaited -- the same
/// results in the same order, with the concurrency between a commit and
/// the reads that follow it collapsed. Name the handle through
/// [`BlockingHandle`] so both shapes stay in step.
#[cfg(turmoil)]
pub(crate) fn spawn_blocking<F, R>(f: F) -> BlockingHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    std::future::ready(Ok(f()))
}

/// On-demand sync's default hydration timeout -- `hydrate_file`'s own
/// on-access path (a caller like an OS read callback blocked on this) and
/// the Convergence Engine's own "eager rehydrate" audit
/// (`rematerialize_one_record`'s two call sites), where a longer wait has
/// real costs unrelated to bulk-transfer size: a longer window for the
/// `verify_write_target`/root-identity re-check race `hydrate_file_with_
/// timeout_locked`'s own doc comment describes, and a longer per-tick
/// latency for the audit sweep (`MAX_PEERS_PER_TICK` sequential candidates
/// per tick). The large-file materialize path (`materialize`'s
/// `ensure_blocks_present` call) deliberately does NOT use this constant -- see `PeerSyncSession::
/// BULK_MATERIALIZE_TIMEOUT`'s own doc comment for why it needs a
/// different, decoupled budget instead of a larger version of this one.
pub const DEFAULT_HYDRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Neutral cadence shared by low-frequency convergence maintenance: a
/// session periodically re-announces its signed native frontier, while the
/// daemon's disk-reconcile backstop performs its independent add-only root
/// walk. Ninety seconds bounds recovery latency without making either
/// maintenance scan/chatty enough to dominate normal synchronization.
pub const DEFAULT_MAINTENANCE_RECONCILE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(90);

/// This session's *current*
/// view of which folder groups its peer is authorized for, as distinct
/// from `PeerSyncSession::shared_group_ids` (the snapshot captured once at
/// construction from whatever netmap/ACL state was available at connect
/// time).
///
/// Push model, not per-request coordination-plane checks:
/// nothing in this crate ever calls back to the coordination plane to
/// populate or consult this. It is a purely local, cheaply-read cache — a
/// `Mutex`-guarded `HashSet` lookup per request, no I/O, no network round
/// trip — that a caller outside this crate (the daemon's netmap-diff-driven
/// teardown reaction) is expected to keep in sync
/// with the actual current netmap/ACL state via
/// `PeerSyncSession::revoke_group`/`grant_group`/`set_authorized_groups`
/// whenever a netmap update changes this peer's authorized groups. Until
/// that daemon-level wiring calls one of those, this starts out — and
/// remains — identical to `shared_group_ids`, i.e. every existing caller
/// that never touches the new methods sees exactly the pre-existing
/// behavior.
#[derive(Debug)]
struct LiveGroupAuthorization {
    groups: StdMutex<std::collections::HashSet<String>>,
}

impl LiveGroupAuthorization {
    fn new(initial: &[String]) -> Self {
        Self { groups: StdMutex::new(initial.iter().cloned().collect()) }
    }

    fn contains(&self, group_id: &str) -> bool {
        self.groups.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains(group_id)
    }

    fn revoke(&self, group_id: &str) {
        self.groups.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(group_id);
    }

    fn grant(&self, group_id: &str) {
        self.groups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group_id.to_string());
    }

    /// Replaces the set; returns whether it differed from the one it replaced.
    fn set(&self, group_ids: impl IntoIterator<Item = String>) -> bool {
        let new: std::collections::HashSet<String> = group_ids.into_iter().collect();
        let mut groups = self.groups.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let changed = *groups != new;
        *groups = new;
        changed
    }
}

pub struct PeerSyncSession {
    /// The wire format. One concrete zero-sized codec: every peer that
    /// reaches a session is the same protocol generation, so there is
    /// nothing to negotiate and nothing to substitute.
    codec: yadorilink_sync_wire::ProtobufPeerWireCodec,
    local_device_id: String,
    peer_device_id: String,
    /// This session's only remaining direct dependency on replica state --
    /// everything else it once needed (`ReplicaHistoryPort`/
    /// `ChangeAdmissionPort`/`FrontierStorePort`/`DurabilityEvidencePort`)
    /// is now built into `replica_engine` below, by the caller, before
    /// construction. This narrow port exists specifically so this session
    /// never again needs to hold the whole replica-state surface merely to
    /// reach one operation.
    block_serve_authorizer: Arc<dyn crate::ports::BlockServeAuthorizationPort>,
    // On the `BlockContentStore` port: three call sites (`materialize`'s and
    // `hydrate_file_with_timeout`'s reconstruct steps) forward this straight
    // into `chunker::reconstruct_file`, which now takes `&dyn
    // BlockContentStore` — the same port `materialization.rs`'s
    // `reconstruct_file_journaled`/`repair_interrupted_materializations_inner`
    // forward into, so this field only ever needs `get`/`put`/
    // `present_blocks`.
    store: Arc<dyn crate::ports::BlockContentStore>,
    /// native state/index-mutation logic that is true regardless of which peer sent
    /// the message, extracted out of this file's own handlers one handler
    /// at a time into `yadorilink-replica-engine` -- see that crate's own
    /// doc comment. Built by the caller (the daemon's own composition
    /// root, directly against `ReplicaCoordinator` -- see
    /// `yadorilink_daemon::replica_coordinator::engine_ports::
    /// build_peer_replica_engine`) and handed in ready-made: this session
    /// does not assemble its own dependencies out of a bigger state
    /// object, so there is nothing here to build lazily.
    pub replica_engine: yadorilink_replica_engine::PeerReplicaEngine,
    /// The folder groups both this device and the peer are authorized for
    /// (determined by the caller from the coordination plane's ACLs —
    /// this crate has no concept of authorization itself): seeded at
    /// construction and mutable afterwards. Consulted by `shares_group`
    /// (and therefore by every per-request authorization check that calls
    /// it — `handle_block_request`).
    live_authorized_groups: LiveGroupAuthorization,
    /// This session's shared, device-wide block-serving credit/coalescing
    /// engine, set once by `DaemonState` after construction (see
    /// `block_serve::BlockServeEngine`'s own doc comment for why this is a
    /// setter rather than a constructor parameter). `None` until set, and
    /// for every test that never calls the setter -- `handle_block_request`
    /// falls back to today's ungated direct-serve behavior whenever this is
    /// `None`, regardless of what the peer advertised.
    block_serve_engine: std::sync::Mutex<Option<Arc<crate::block_serve::BlockServeEngine>>>,
    /// This device's own effective ignore
    /// pattern set for each shared group, keyed the same way as
    /// `sync_roots`. Ignore patterns are device-local and unsynced —
    /// this is *this* device's filter on what it accepts
    /// from a peer, entirely independent of whatever the sending peer (or
    /// this device's other peers) chooses to do with the same path.
    ///
    /// Originally loaded once at construction only, the same way
    /// `canonical_sync_roots` is: a `.yadorilinkignore` edit took effect
    /// for incoming records on this peer's *next* session (a fresh
    /// `PeerSyncSession`), not live mid-session — deliberate, since local
    /// scanning/watching (`link_manager`'s executor,
    /// `EffectiveIgnoreSet::load_for_link_root` reloaded fresh on every
    /// call there) already picks up the edit immediately for the LOCAL
    /// side. But a long-lived peer connection has no bound on how stale
    /// this cached set could get for the PEER-reconciliation side, and
    /// nothing else ever forced a reconnect — a review finding flagged
    /// this as an unbounded `IgnoreExcluded` liveness gap. Each entry now
    /// pairs its `EffectiveIgnoreSet` with the `Instant` it was loaded;
    /// `effective_ignore_set` reloads from the group's live root once an
    /// entry is older than `IGNORE_SET_REFRESH_INTERVAL`, capping the
    /// worst-case staleness instead of removing the cache outright (a
    /// reload on every lookup would cost a disk read+parse per path on
    /// the hot reconciliation loop `is_locally_ignored` runs in).
    /// How many block fetches to this peer are in flight right now -- read
    /// by `fetch_block_raw` at the moment a request goes out, so the
    /// adaptive window can tell a measurable round trip from one whose
    /// latency is really a sibling's service time. See
    /// `InFlightBlockFetchGuard`'s own doc comment.
    in_flight_block_fetches: std::sync::atomic::AtomicUsize,
    /// Cumulative block body bytes this session has received from this
    /// peer, counted the instant a block's body comes off its stream --
    /// before decompression or storage. This is real block CONTENT, not general
    /// wire traffic: unlike a socket-level byte counter (every UDP
    /// payload the device's socket sees -- handshake, keepalive, control,
    /// metadata, and every other message type too), a caller watching this
    /// counter for its first increase past a baseline observes the instant
    /// this peer started receiving THIS block's bytes, not merely "some
    /// packet arrived." Exists for `yadorilink-bench`'s `T_firstbyte`
    /// metric (see that crate's L1 scenario), which needed a materially
    /// tighter signal than the wire-byte proxy it started with -- but reads
    /// nothing content-identifying (a running byte count only), so it costs
    /// nothing to leave wired in production.
    content_bytes_received: std::sync::atomic::AtomicU64,
    /// [`SERVICE_RPC_DEADLINE`] in milliseconds, per session so a test that
    /// shortens it cannot affect another session in the same process.
    service_rpc_deadline_ms: std::sync::atomic::AtomicU64,
    /// The peer sent a service RPC of another `RPC_VERSION`. Sticky for the life of the session
    /// (a peer that updates reconnects with a new one): the peer is reachable but cannot be
    /// counted on for anything custody depends on.
    rpc_version_mismatch: std::sync::atomic::AtomicBool,
    /// This session's upload/
    /// download token buckets, gating `handle_block_request`'s outbound
    /// send and `fetch_block`'s inbound receive respectively. Starts
    /// unlimited (mirroring every other field here that needs a
    /// mutable-after-construction default — see `live_authorized_groups`);
    /// `set_rate_limiters` replaces it with the daemon's shared, global
    /// pair (`yadorilink-daemon::peer_orchestrator`) so every session, and
    /// the daemon's hydration dispatcher (which calls `fetch_block`
    /// directly — the same choke point), draw down one ceiling per
    /// direction rather than each getting an independent full-rate
    /// allowance. Wrapped in a mutex (not `ArcSwap`) since this
    /// is only read once per block send/receive, not a hot per-byte path.
    rate_limiters: StdMutex<Arc<RateLimiters>>,
    /// This session's AIMD in-flight
    /// block-fetch window controller — see `adaptive_window` module doc
    /// comment. Fed real outcomes by `fetch_block` (success + observed
    /// RTT) and by `record_fetch_timeout` (a caller-observed missing
    /// reply); read by `fetch_window` — the daemon's multi-peer dispatcher
    /// consults this in place of the old fixed per-candidate lane count.
    adaptive_window: AdaptiveWindow,
    /// Everything this session needs to reach its peer: block streams,
    /// service RPC streams, and where a bootstrap snapshot is
    /// published/collected. A REQUIRED constructor parameter -- see
    /// `SessionTransports`'s own doc comment. Not behind a `StdMutex`
    /// like the fields it replaced: it is set once, at construction, and
    /// never replaced, so there is nothing to guard.
    transports: crate::ports::SessionTransports,
    /// This session's caller-injected bridge to the daemon's own
    /// coordination-plane-backed lease machinery (`DaemonState::request_
    /// handoff_lease`) — see `HandoffLeaseResponder`'s doc comment. Set once
    /// at construction; a caller with no real responder passes a
    /// deny-by-default implementation, so an incoming `HandoffLeaseRequest`
    /// answers `granted = false` rather than panic or hang.
    handoff_lease_responder: Arc<dyn HandoffLeaseResponder>,
    /// This session's caller-injected bridge to the daemon's own
    /// removed-device-ticket machinery (`DaemonState::obtain_own_handoff_
    /// ticket`) -- see `HandoffTicketResponder`'s doc comment. Set once at
    /// construction; a caller with no real responder passes a
    /// deny-by-default implementation, so an incoming `HandoffTicketRequest`
    /// answers `granted = false` rather than panic or hang.
    handoff_ticket_responder: Arc<dyn HandoffTicketResponder>,
    /// This session's bridge to the daemon's custody holds, answering a full
    /// replica that asks this device to move custody off it -- see
    /// `CustodyRehomeResponder`. A caller with no real responder passes a
    /// deny-by-default one.
    custody_rehome_responder: Arc<dyn CustodyRehomeResponder>,
}

impl PeerSyncSession {
    /// A session with its peer: everything it sends and receives rides
    /// `transports`.
    ///
    /// What the daemon builds for a peer that is authorized and reachable
    /// over the iroh substrate. Block and service requests, in both
    /// directions, and snapshot transfers all go through `transports`, so
    /// nothing this session does for its peer needs a second connection. It
    /// has no loop of its own; its lifetime is its owner's.
    ///
    /// `shared_group_ids` seeds the live authorization view; `deps` carries
    /// the capability injections (see [`PeerSyncSessionDeps`]).
    /// `replica_engine` and
    /// `block_serve_authorizer` come already built: the caller owns replica
    /// state, so it builds the narrow ports this session depends on.
    #[allow(clippy::too_many_arguments)]
    pub fn over_substrate(
        local_device_id: String,
        peer_device_id: String,
        block_serve_authorizer: Arc<dyn crate::ports::BlockServeAuthorizationPort>,
        replica_engine: yadorilink_replica_engine::PeerReplicaEngine,
        store: Arc<dyn crate::ports::BlockContentStore>,
        shared_group_ids: Vec<String>,
        transports: crate::ports::SessionTransports,
        deps: PeerSyncSessionDeps,
    ) -> Arc<Self> {
        let live_authorized_groups = LiveGroupAuthorization::new(&shared_group_ids);
        Arc::new(Self {
            codec: yadorilink_sync_wire::ProtobufPeerWireCodec,
            local_device_id,
            peer_device_id,
            block_serve_authorizer,
            store,
            replica_engine,
            live_authorized_groups,
            block_serve_engine: std::sync::Mutex::new(deps.block_serve_engine),
            in_flight_block_fetches: std::sync::atomic::AtomicUsize::new(0),
            content_bytes_received: std::sync::atomic::AtomicU64::new(0),
            rpc_version_mismatch: std::sync::atomic::AtomicBool::new(false),
            service_rpc_deadline_ms: std::sync::atomic::AtomicU64::new(
                SERVICE_RPC_DEADLINE.as_millis() as u64,
            ),
            rate_limiters: StdMutex::new(deps.rate_limiters),
            adaptive_window: AdaptiveWindow::new(
                ADAPTIVE_WINDOW_INITIAL,
                ADAPTIVE_WINDOW_MIN,
                MAX_IN_FLIGHT_MESSAGES_PER_PEER,
                MAX_IN_FLIGHT_MESSAGES_PER_PEER,
            ),
            transports,
            handoff_lease_responder: deps.handoff_lease_responder,
            handoff_ticket_responder: deps.handoff_ticket_responder,
            custody_rehome_responder: deps.custody_rehome_responder,
        })
    }

    /// Replaces this session's upload/download token buckets with
    /// the daemon's shared, global pair (see `RateLimiters`'s doc comment)
    /// so this session's block sends/receives draw down the same ceiling
    /// every other session — and the daemon's hydration dispatcher, which
    /// calls `fetch_block` directly — shares, rather than
    /// getting an independent full-rate allowance. Mirrors
    /// `set_authorized_groups`'s mutable-after-construction pattern:
    /// existing constructors are unchanged, and the daemon injects the
    /// shared limiters once a session is constructed (`peer_orchestrator.rs`).
    pub fn set_rate_limiters(&self, limiters: Arc<RateLimiters>) {
        *self.rate_limiters.lock().unwrap_or_else(|p| p.into_inner()) = limiters;
    }

    fn rate_limiters(&self) -> Arc<RateLimiters> {
        self.rate_limiters.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Whether `group_id` is one this session's peer is *currently*
    /// authorized (per the coordination plane's ACL) to sync with us.
    ///
    /// sync-engine spec "Block Requests Are Authorized Against Actual Group
    /// Membership":
    /// reads `live_authorized_groups`, seeded at session construction and
    /// updated as authorization changes — every caller of this method
    /// (`handle_block_request`) already
    /// calls it fresh on every single
    /// incoming request/message, so re-pointing its data source at a
    /// live-updatable set is what turns "checked once at session start"
    /// into "re-validated against current state at processing time" for
    /// all of them, with no change needed at any call site. Cheap on the
    /// common (still-authorized) path — one `Mutex`-guarded `HashSet`
    /// lookup, no coordination-plane round trip — consistent with a
    /// push model.
    pub fn shares_group(&self, group_id: &str) -> bool {
        self.live_authorized_groups.contains(group_id)
    }

    /// Withdraws this peer's
    /// authorization for `group_id`, effective for the very next request
    /// `shares_group` is asked about — called by daemon-level
    /// netmap-diff-driven teardown when a netmap
    /// update removes this peer's edge for `group_id` (`share revoke`), or
    /// once per remaining shared group when the peer is removed entirely
    /// (`device remove`). Does not touch `shared_group_ids` (the
    /// construction-time snapshot) or tear down the peer's connection —
    /// that transport-level teardown is a separate, independent reaction to
    /// the same netmap update, not this method's job.
    pub fn revoke_group(&self, group_id: &str) {
        self.live_authorized_groups.revoke(group_id);
    }

    /// The inverse of `revoke_group`: grants (or re-grants) this peer's
    /// authorization for `group_id`, effective for the next request. Kept
    /// symmetric with `revoke_group` for a netmap update that adds a group
    /// edge, e.g. `share grant` while this session is already established.
    pub fn grant_group(&self, group_id: &str) {
        self.live_authorized_groups.grant(group_id);
    }

    /// Replaces the entire live-authorized-group set at once — useful when
    /// the caller already has the full, current list of groups this peer
    /// shares (e.g. recomputed from a fresh netmap) rather than a single
    /// added/removed edge. Returns whether the set actually changed.
    pub fn set_authorized_groups(&self, group_ids: impl IntoIterator<Item = String>) -> bool {
        self.live_authorized_groups.set(group_ids)
    }

    /// Cumulative block body bytes received from this peer so far -- see
    /// `content_bytes_received`'s own field doc comment for why this is a
    /// materially tighter signal than a generic wire-byte counter for "has
    /// this session started receiving real block content."
    pub fn content_bytes_received(&self) -> u64 {
        self.content_bytes_received.load(std::sync::atomic::Ordering::Relaxed)
    }
}

fn block_data_matches(block: &BlockInfo, data: &[u8]) -> bool {
    if data.len() != block.size as usize {
        return false;
    }
    let digest = Sha256::digest(data);
    digest[..] == block.hash[..]
}

/// a peer
/// could return data for a block that doesn't actually match what was
/// requested (wrong content, truncated, or an outright malicious/corrupt
/// response) — `ensure_blocks_present` must never accept and persist it
/// as though it were the real block.
#[cfg(test)]
mod block_data_matches_tests;

/// `compress_block`/`decompress_block`
/// exercised directly — no `PeerSyncSession`/channel needed, mirroring
/// every other free-function test module above.
#[cfg(test)]
mod compression_codec_tests;

/// Bytes-on-wire and wall-clock cost for `compress_block` — the exact
/// codec `handle_block_request`/ `send_full_index`/`send_index_update` all
/// call — against two representative workloads: a source-tree-like text
/// corpus (compression's target case) and a photo/media-like
/// incompressible corpus (the adaptive-skip heuristic's target case,
/// confirming the adaptive skip heuristic keeps the regression
/// negligible).
#[cfg(test)]
mod compression_benchmark;

#[cfg(test)]
mod dag_resolution_tests;

#[cfg(all(test, unix))]
mod disk_race_fingerprint_tests {
    use yadorilink_fs_platform::fs_identity::disk_race_fingerprint;

    /// How many write+observe cycles
    /// [`ctime_can_distinguish_back_to_back_writes`] samples before
    /// concluding this filesystem's ctime clock cannot be relied on to
    /// separate two back-to-back writes to the same file. Same technique,
    /// and the same sample count, as `fs_capabilities`'s
    /// `probe_birth_time_granularity`: a coarse clock reliably collides at
    /// least once across this many samples, and this is cheap enough to
    /// run inline in a unit test.
    const CTIME_GRANULARITY_SAMPLE_COUNT: usize = 32;

    /// Measures, empirically and inline, whether `path`'s filesystem
    /// advances ctime finely enough to distinguish two consecutive writes
    /// to the same file — the specific clock `disk_race_fingerprint`
    /// leans on once mtime has been restored to an identical value (see
    /// the test below). Deliberately NOT `cfg(target_os = ...)`: this is a
    /// filesystem property, not an OS property — an overlayfs mount on
    /// Linux and APFS on macOS differ for reasons the target triple
    /// doesn't capture, and `fs_capabilities`'s own birth-time granularity
    /// probe is not reused here because a birth-time clock and a ctime
    /// clock are not assumed to share a resolution; this measures ctime
    /// directly instead of assuming.
    ///
    /// `path` must already exist. Writes to it repeatedly (content only —
    /// ctime advances on any metadata-affecting change, not specifically
    /// on a length change, so the probe writes are not required to match
    /// any particular length) and looks for two consecutive samples whose
    /// `disk_race_fingerprint` is byte-identical: a collision is the only
    /// observation a coarse clock can produce that a fine one cannot (the
    /// same reasoning `probe_birth_time_granularity`'s own doc comment
    /// gives for treating collision, not small-delta, as the sole proof).
    fn ctime_can_distinguish_back_to_back_writes(path: &std::path::Path) -> bool {
        let mut previous = disk_race_fingerprint(path);
        for i in 0..CTIME_GRANULARITY_SAMPLE_COUNT {
            std::fs::write(path, format!("granularity-probe-{i}").as_bytes()).unwrap();
            let sample = disk_race_fingerprint(path);
            if sample == previous {
                return false;
            }
            previous = sample;
        }
        true
    }

    /// The case the original `(len, mtime)` form of this check could not
    /// see: an overwrite of exactly the same length whose mtime is then
    /// restored to the original value. A real local editor doing a
    /// same-size in-place write inside the filesystem's mtime granularity
    /// presents this way, and letting it through means `materialize`
    /// silently destroys that edit — the failure mode the check exists to
    /// prevent, so it must not be the one case it misses.
    ///
    /// With the mtime restored, only ctime can still distinguish the
    /// writes — and ctime's real-world resolution varies by filesystem,
    /// not by OS (measured: overlayfs on x86_64 Linux advances ctime in
    /// ~4ms quanta, so a tight write-restore-observe sequence can complete
    /// inside one tick; APFS on macOS does not exhibit this). Where this
    /// run's filesystem can distinguish two back-to-back writes (proven
    /// empirically by [`ctime_can_distinguish_back_to_back_writes`], not
    /// assumed from `cfg(target_os = ...)`), the fingerprint itself must
    /// still change, exactly as before. Where it cannot, the fingerprint
    /// provably has no observable signal left to detect the overwrite
    /// with — `stat` reports nothing else that differs — so this asserts
    /// the guard that actually protects the user in that case instead:
    /// `yadorilink_local_storage::disk_bytes_match_indexed_blocks` is
    /// content-based, not clock-based, and correctly reports that the
    /// on-disk bytes no longer match what was indexed.
    ///
    /// Scope of this guarantee: in production, `materialize`'s content-hash guard
    /// (`peer_session.rs`,
    /// gated on `local_row` — see the `locally_hydrated` check ahead of
    /// its `disk_bytes_match_indexed_blocks` call) only runs when the
    /// path's materialization state is already `Present`. For
    /// `Remote`/`Hydrating`/`Evicting` — states whose whole point is
    /// to disagree with what's on disk — neither guard catches a
    /// same-tick, same-length overwrite with a restored mtime on a
    /// coarse-ctime filesystem. That window is covered by atomic preimage
    /// capture, not by a metadata or content check performed after the
    /// fact, which cannot close it.
    #[test]
    fn a_same_length_overwrite_with_a_restored_mtime_still_changes_the_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("same-length.bin");
        std::fs::write(&path, b"AAAA").unwrap();

        let probe_path = dir.path().join("granularity-probe.bin");
        std::fs::write(&probe_path, b"seed").unwrap();
        let ctime_is_fine = ctime_can_distinguish_back_to_back_writes(&probe_path);
        // Diagnostic only, unconditional: which branch a given CI runner's
        // filesystem actually took is exactly the fact this test's own
        // history (a residual gap discovered by mismatched CI/local
        // behavior) shows is worth having in the log rather than inferred
        // after the fact.
        eprintln!(
            "disk_race_fingerprint_tests: this filesystem's ctime clock is {}",
            if ctime_is_fine {
                "fine (metadata fingerprint assertion)"
            } else {
                "coarse (content-hash fallback assertion)"
            }
        );

        let before = disk_race_fingerprint(&path).expect("file exists");
        let original_mtime = std::fs::symlink_metadata(&path).unwrap().modified().unwrap();

        std::fs::write(&path, b"BBBB").unwrap();
        // Restore the mtime exactly, the same way `dst_support::fs_ops::stamp`
        // does — no extra dependency, and it proves the mtime really is
        // byte-identical rather than merely close.
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().modified().unwrap(),
            original_mtime,
            "precondition: the mtime was restored exactly, so only ctime can betray the write"
        );
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().len(),
            4,
            "precondition: the overwrite kept the length identical"
        );

        let after = disk_race_fingerprint(&path).expect("file still exists");

        if ctime_is_fine {
            assert_ne!(
                before, after,
                "a same-length overwrite with a restored mtime must still be detected on a \
                 filesystem whose ctime clock can distinguish it -- letting it through is \
                 exactly the silent local-edit loss this guards"
            );
        } else {
            // The metadata fingerprint provably cannot see this write: len,
            // mtime, and (on this filesystem, per the probe above) ctime are
            // all identical to `before`. That is not a bug in the
            // fingerprint -- there is nothing left in `stat` for it to read.
            // Assert the guard that actually catches this case instead.
            let original_block = yadorilink_replica_domain::file::BlockInfo {
                hash: {
                    use sha2::{Digest, Sha256};
                    Sha256::digest(b"AAAA").to_vec()
                },
                offset: 0,
                size: 4,
            };
            let content_still_matches_original =
                yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                    &path,
                    std::slice::from_ref(&original_block),
                )
                .unwrap();
            assert!(
                !content_still_matches_original,
                "the metadata fingerprint has no signal left on this coarse-ctime filesystem, \
                 so the content-hash guard must be the one to catch the overwrite instead"
            );
        }
    }

    /// The other direction: an untouched file must fingerprint identically,
    /// or every eager materialize would decline itself into a retry loop on
    /// a path nobody is racing.
    #[test]
    fn an_untouched_file_fingerprints_identically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("untouched.bin");
        std::fs::write(&path, b"stable").unwrap();

        let first = disk_race_fingerprint(&path);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = disk_race_fingerprint(&path);

        assert_eq!(first, second, "an untouched file must not look like a racing write");
    }

    /// A path that does not exist fingerprints as `None` on both samples,
    /// so a materialize creating a brand-new file is never declined.
    #[test]
    fn a_missing_path_fingerprints_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(disk_race_fingerprint(&dir.path().join("absent.bin")), None);
    }
}

impl crate::convergence_driver::ConvergenceDriver for PeerSyncSession {
    fn peer_device_id(&self) -> &str {
        &self.peer_device_id
    }

    fn fetch_block<'a>(
        &'a self,
        group_id: &'a str,
        file_path: &'a str,
        block: &'a BlockInfo,
        timeout: std::time::Duration,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<crate::convergence_driver::FetchedBlock, PeerSessionError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let mut wire_wait = std::time::Duration::ZERO;
            let outcome = PeerSyncSession::fetch_one_block(
                self,
                group_id,
                file_path,
                block,
                timeout,
                &mut wire_wait,
            )
            .await?;
            Ok(crate::convergence_driver::FetchedBlock {
                outcome: match outcome {
                    BlockFetchOutcome::Fetched { hash, data } => {
                        crate::convergence_driver::BlockFetch::Fetched { hash, data }
                    }
                    BlockFetchOutcome::Missing => crate::convergence_driver::BlockFetch::Missing,
                    BlockFetchOutcome::VerifiedRefusal { reason } => {
                        crate::convergence_driver::BlockFetch::VerifiedRefusal { reason }
                    }
                },
                wire_wait,
            })
        })
    }
}
