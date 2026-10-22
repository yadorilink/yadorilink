//! Hydration no longer tries one whole-file transfer per peer
//! sequentially. A file's missing blocks are partitioned across every
//! currently-reachable, authorized peer session and fetched concurrently,
//! with a block a peer reports not-found reassigned to a different peer
//! rather than failing the whole attempt, and a single file-level deadline
//! covering the entire dispatch.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};

use crate::sync_error::SyncError;
use futures_util::stream::{FuturesUnordered, StreamExt};
use sha2::{Digest, Sha256};
use yadorilink_filesystem_sync::materialization_eviction::{evict_file, MaterializationContext};
use yadorilink_local_storage::{disk_bytes_match_indexed_blocks, BlockStore, StorageError};
use yadorilink_peer_session::peer_session::{BlockFetchAnswer, PeerSyncSession};
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_sync_sqlite::exact_materialized_commit::InternalMaterializedCommit;
#[cfg(test)]
use yadorilink_sync_sqlite::exact_materialized_commit::{
    ExactMaterializedState, ExpectedAuthoring,
};

use crate::daemon_state::{run_blocking_sweep_offloaded, DaemonState};

mod range_window;

/// A single deadline for the *entire* multi-session dispatch —
/// supersedes what used to be the former per-session hydrate's per-session
/// timeout for the daemon-orchestrated hydration path. Same value as
/// `PeerSyncSession::DEFAULT_HYDRATION_TIMEOUT` (unchanged budget, moved
/// ownership).
pub(crate) const HYDRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Per-block bound on a single `PeerSyncSession::fetch_block` call inside
/// `fetch_blocks_from_sessions`'s worker loop. Diagnosed
/// via an instrumented, reproducible run of
/// `yadorilink-daemon/tests/multi_peer_hydration.rs`: `fetch_block` sends its
/// `BlockRequest` and the peer's `handle_block_request` logs a successful
/// `send` of the matching `BlockResponse` (so the peer *did* answer), yet
/// the requester's `PeerChannel::recv` loop never observes that response
/// arriving — an occasional lost/undelivered message on an otherwise fully
/// responsive, connected session, reproducible specifically under this
/// test's burst of several simultaneous peer connections. Before this
/// constant existed, a worker's `session.fetch_block(...).await` had no
/// bound of its own, so one unlucky request silently ate the *entire*
/// file-level `HYDRATION_TIMEOUT` budget — that worker's task simply never
/// returned, `workers.join_next` never observed it finish, and the whole
/// dispatch (every other, already-successful block included) sat blocked
/// until the outer deadline in `hydrate_with_timeout` finally tore
/// everything down, turning one dropped response into a full-file failure
/// instead of a quick reassignment. `BlockWorkQueue::mark_not_found`
/// already exists precisely to reassign a block a peer explicitly reports
/// missing to a different candidate (or retry it later); wrapping each
/// fetch in this timeout and routing an expired one through the same
/// `mark_not_found` path extends that existing resilience to a request
/// that never gets *any* answer, not just an explicit not-found one —
/// without touching `PeerSyncSession` or the transport layer itself.
/// Deliberately much shorter than `HYDRATION_TIMEOUT`: the whole point is
/// to free up a stuck worker to try the next candidate long before the
/// file-level deadline would otherwise be spent waiting on it alone.
///
/// Sized per block, not a fixed constant: [`PeerSyncSession::fetch_
/// response_timeout_for`]'s own doc comment has the measurement (8
/// concurrent 128KiB fetches sharing one relay-forwarded session
/// genuinely needed 13.3-14.3s each) behind why a single fixed deadline
/// undercounts a block-fetch sharing a connection with several concurrent
/// siblings. This wrap must stay strictly above that inner deadline with
/// real margin (below, `PER_BLOCK_FETCH_TIMEOUT_MARGIN`) -- it exists
/// specifically to catch `fetch_block_sized` itself hanging past its own
/// internal bound (a bug, not the ordinary case), so setting it equal to
/// the inner deadline would make this wrap preempt that deadline before
/// it ever gets a chance to fire on its own.
fn per_block_fetch_timeout(block_size: u64) -> std::time::Duration {
    PeerSyncSession::fetch_response_timeout_for(block_size) + PER_BLOCK_FETCH_TIMEOUT_MARGIN
}

const PER_BLOCK_FETCH_TIMEOUT_MARGIN: std::time::Duration = std::time::Duration::from_secs(2);

/// Small scheduling margin added atop `2 *` the largest still-missing
/// block's own response deadline when deriving a stall budget (see
/// `HydrationStallTracker`'s own doc comment). `2x`, not `1x`: at
/// `AdaptiveWindow`'s floor of a single in-flight request, one genuine
/// per-block timeout can consume nearly the whole per-block deadline by
/// itself, so the stall budget must leave room for that AND one full
/// follow-up attempt, not just one.
const STALL_BUDGET_MARGIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Tracks durable block-fetch progress for one `hydrate`/`hydrate_with_
/// timeout` call, so `run_with_stall_deadline` can fail on genuine
/// inactivity -- no block has durably completed in a while -- instead of
/// on a fixed wall-clock ceiling for the whole multi-block dispatch.
///
/// A fixed absolute deadline (this module's previous design: a single
/// `tokio::time::timeout` around the whole `hydrate_inner` call) cannot
/// tell "no reachable candidate can serve these blocks" apart from "a
/// large file is transferring correctly, just slower than the deadline
/// assumed" -- both look identical from outside: no result by the
/// deadline. Once `PeerSyncSession::fetch_response_timeout_for` made the
/// per-block deadline size- (and indirectly, contention-) aware, that gap
/// became real: a genuinely-progressing relay-contended transfer could
/// need several times `HYDRATION_TIMEOUT`'s old flat 30s to finish a
/// multi-block file, and the flat deadline would abort it anyway, even
/// though `fetch_blocks_from_sessions` was completing blocks the whole
/// time (confirmed directly: a real relay-recovery run gained 39/48
/// blocks, monotonically, across eight 30s-bounded attempts that each
/// individually "failed").
///
/// `record_progress` is called by `fetch_blocks_from_sessions` every time
/// a block durably completes (CAS write, then this group's provenance for
/// it, both landed) -- exactly the signal that distinguishes stalled from
/// slow. `raise_budget` is called once `resolve_blocks_local_first` knows
/// the actual missing blocks' sizes, so the budget reflects THIS
/// dispatch's own real worst-case per-block wait, not a guess made before
/// any block was known.
struct HydrationStallTracker {
    last_progress: StdMutex<std::time::Instant>,
    stall_budget: StdMutex<std::time::Duration>,
    /// Told how many bytes were fetched, for a requester that shows progress.
    fetched: Option<Arc<crate::application::ports::AssemblyProgress>>,
}

impl HydrationStallTracker {
    fn new(initial_stall_budget: std::time::Duration) -> Self {
        Self {
            last_progress: StdMutex::new(std::time::Instant::now()),
            stall_budget: StdMutex::new(initial_stall_budget),
            fetched: None,
        }
    }

    fn with_progress(
        mut self,
        progress: Option<Arc<crate::application::ports::AssemblyProgress>>,
    ) -> Self {
        self.fetched = progress;
        self
    }

    /// A block of `bytes` became durable.
    fn record_progress(&self, bytes: u64) {
        *self.last_progress.lock().unwrap_or_else(|p| p.into_inner()) = std::time::Instant::now();
        if let Some(fetched) = &self.fetched {
            fetched.advance(bytes);
        }
    }

    /// Raises the stall budget to `candidate` if it's larger than the
    /// current one -- never lowers it. The caller-supplied base (this
    /// call's own `timeout` argument, covering preflight/disk-check work
    /// before any block size is known) and this dispatch's derived,
    /// size-aware minimum both apply; the larger always wins.
    fn raise_budget(&self, candidate: std::time::Duration) {
        let mut budget = self.stall_budget.lock().unwrap_or_else(|p| p.into_inner());
        if candidate > *budget {
            *budget = candidate;
        }
    }

    fn is_stalled(&self) -> bool {
        let budget = *self.stall_budget.lock().unwrap_or_else(|p| p.into_inner());
        self.last_progress.lock().unwrap_or_else(|p| p.into_inner()).elapsed() >= budget
    }
}

/// How often `run_with_stall_deadline` re-checks `HydrationStallTracker::
/// is_stalled` -- frequent enough that a genuine stall is caught promptly
/// relative to any reasonable stall budget, cheap enough (one lock/compare,
/// no I/O) that polling this often costs nothing meaningful.
const STALL_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Runs `future` to completion unless `stall` reports inactivity first, in
/// which case this returns `HydrationFailed` for `path` without waiting
/// for `future` any further. See `HydrationStallTracker`'s own doc comment
/// for why this replaces a flat `tokio::time::timeout` around the whole
/// multi-block dispatch.
async fn run_with_stall_deadline<T>(
    path: &str,
    stall: &HydrationStallTracker,
    future: impl std::future::Future<Output = Result<T, SyncError>>,
) -> Result<T, SyncError> {
    tokio::pin!(future);
    loop {
        tokio::select! {
            result = &mut future => return result,
            _ = tokio::time::sleep(STALL_CHECK_INTERVAL) => {
                if stall.is_stalled() {
                    return Err(SyncError::HydrationFailed(path.to_string()));
                }
            }
        }
    }
}

/// How long an idle worker (one whose last `pop_for` came back empty while
/// `BlockWorkQueue::has_outstanding` was still true) sleeps before
/// re-checking the queue — see `BlockWorkQueue::outstanding`'s doc comment
/// for the worker-starvation race this polling avoids. Short relative to
/// `per_block_fetch_timeout` so a block freed up by a timed-out peer is
/// picked up by a waiting idle worker almost immediately, not after a
/// meaningful further delay.
const WORKER_IDLE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Reuses `fs_identity::disk_race_fingerprint` rather than the plain
/// `(size, mtime)` pair this module used to compute locally: size+mtime
/// alone lets a same-size edit landing within the filesystem's mtime
/// granularity (or from an editor that preserves mtime) slip past the
/// commit-time revalidation below undetected, silently overwriting a
/// concurrent local edit with the just-hydrated remote content — the same
/// race `disk_race_fingerprint`'s own doc comment describes and adds
/// `ctime` to close (unix; the residual gap on other platforms is
/// documented there, not re-derived here).
///
/// Paired with the file's `(device, inode)` from the same `lstat`. An editor
/// that saves by writing a new file and renaming it over the old one gives
/// the path a new inode, and that is caught even where the fingerprint
/// cannot catch it: on a filesystem whose ctime granularity is coarse (or
/// that has no ctime at all), a same-length save whose mtime is set back to
/// the old value inside one granule leaves length, mtime and ctime all
/// equal. What stays uncovered there is an in-place, same-length overwrite
/// with a restored mtime inside that granule: same inode, same fingerprint.
/// On APFS and ext4 ctime has nanosecond resolution and cannot be set from
/// user space, so that residual needs a coarse-ctime filesystem. Closing it
/// would mean hashing the file at every re-check, a full read of it each
/// time.
pub(crate) type DiskIdentity =
    Option<(yadorilink_fs_platform::fs_identity::DiskRaceFingerprint, Option<(u64, u64)>)>;

pub(crate) fn disk_identity(path: &std::path::Path) -> Result<DiskIdentity, SyncError> {
    Ok(std::fs::symlink_metadata(path).ok().as_ref().map(disk_identity_of))
}

pub(crate) fn disk_identity_of(
    meta: &std::fs::Metadata,
) -> (yadorilink_fs_platform::fs_identity::DiskRaceFingerprint, Option<(u64, u64)>) {
    #[cfg(unix)]
    let file_id = {
        use std::os::unix::fs::MetadataExt as _;
        Some((meta.dev(), meta.ino()))
    };
    #[cfg(not(unix))]
    let file_id = None;
    (yadorilink_fs_platform::fs_identity::disk_race_fingerprint_of(meta), file_id)
}

/// Journals `path` dirty when the file on disk is no longer the one the
/// hydration attempt took as its baseline, and answers whether it was.
///
/// Called where an attempt refuses because the file changed under it. The
/// refusal alone does not protect the edit it saw: dropping the attempt's
/// guard puts the row back to `Remote`, and the next attempt samples
/// the file as it is then -- the edit -- as its own baseline, finds it
/// unchanged, and renames the remote content over it. Until the watcher
/// journals the edit, nothing else stands in the way. So the refusal
/// records it itself, under the path lock and before the guard drops:
/// every later attempt's commit decision then sees the path dirty and
/// refuses, until local capture has taken the edit and cleared the row. A
/// row for content that turns out to be unchanged is cleared by the
/// dirty-journal backstop without producing an edit.
fn journal_local_edit_seen_by_hydration(
    state: &DaemonState,
    group_id: &str,
    path: &str,
    out_path: &std::path::Path,
    baseline: DiskIdentity,
    permit: &yadorilink_root_authority::root_commit::RootCommitPermit<'_>,
) -> Result<bool, SyncError> {
    let now = disk_identity(out_path)?;
    if now == baseline {
        return Ok(false);
    }
    state.replica_coordinator.journal_uncaptured_local_edit(
        group_id,
        path,
        now.is_some(),
        permit,
    )?;
    Ok(true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HydrationCommitDecision {
    Commit,
    AlreadyComplete,
    Stale,
}

/// Restores the proof for a path that is `Present`, whose on-disk state
/// -- bytes, mode and xattrs, which is the whole of what `version` is a
/// hash over -- the caller has just compared against the current row
/// under that row's path lock, and whose standing proof names a version
/// the row has moved off.
///
/// The healing lane, deliberately not a physical writer's: nothing was
/// mutated, so there is no epoch of its own to CAS against, and inventing
/// one by bumping the fence would claim a mutation that never happened and
/// invalidate whatever evidence a concurrent internal mutator is holding.
/// `reprove_hydrated_file` publishes under the LIVE fence
/// instead, guarded on the row this call verified against -- so a
/// supersession landing between the byte comparison and the commit writes
/// nothing and answers `false`, and the caller fails closed.
///
/// `version` is the caller's, from the one row read it
/// performed under the path lock and compared disk against. They are
/// deliberately not re-read here: a proof has to name the version whose
/// state was actually verified, and a fresh read is a different
/// incarnation with no comparison behind it. Its `expected_version`
/// guard then means what it says -- "the row still names the
/// version this evidence is about" -- rather than "the row still names
/// whatever it named a moment ago".
fn heal_hydrated_proof_for_current_version(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    out_path: &std::path::Path,
    version: &yadorilink_replica_domain::ids::VersionHash,
    permit: &yadorilink_root_authority::root_commit::RootCommitPermit<'_>,
) -> Result<bool, SyncError> {
    // An observation that fails costs the re-prove, nothing else: the
    // claim stays unproven and the caller fails closed, which is where it
    // was already heading.
    let Ok(identity) = yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(out_path)
    else {
        return Ok(false);
    };
    Ok(state
        .replica_coordinator
        .reprove_hydrated_file(group_id, path, version, identity, permit)?)
}

fn hydration_commit_decision(
    state: &DaemonState,
    group_id: &str,
    path: &str,
    expected_record: &yadorilink_replica_domain::file::FileRecord,
    expected_root: &std::path::Path,
    out_path: &std::path::Path,
    expected_disk_identity: DiskIdentity,
) -> Result<HydrationCommitDecision, SyncError> {
    if state.replica_coordinator.file_index_repository().get_file(group_id, path)?.as_ref()
        != Some(expected_record)
        || state.replica_coordinator.dirty_path_repository().is_path_dirty(group_id, path)?
    {
        return Ok(HydrationCommitDecision::Stale);
    }
    // `out_path` was resolved from `expected_root` at hydration start, before
    // the (possibly multi-second) block fetch. `local_root_for_group` reads
    // the live link table fresh every call (see its own doc comment) rather
    // than caching, so re-resolving here and comparing catches a group that
    // was unlinked and relinked elsewhere -- or simply unlinked outright --
    // during the fetch: without this, the commit below would still write to
    // `out_path`, a root the live link table no longer has any row for.
    // `peer_session::PeerSyncSession::sync_root` already applies this same
    // "re-read on every write, never trust a root captured earlier" rule for
    // its own materialize path; this closes the same gap for hydration.
    if local_root_for_group(state, group_id).ok().as_deref() != Some(expected_root) {
        return Ok(HydrationCommitDecision::Stale);
    }
    match state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(group_id, path)?
    {
        Some(MaterializationState::Present)
            if disk_bytes_match_indexed_blocks(out_path, &expected_record.blocks)? =>
        {
            Ok(HydrationCommitDecision::AlreadyComplete)
        }
        Some(MaterializationState::Hydrating)
            if disk_identity(out_path)? == expected_disk_identity =>
        {
            Ok(HydrationCommitDecision::Commit)
        }
        _ => Ok(HydrationCommitDecision::Stale),
    }
}

// In-flight window: `fetch_blocks_from_sessions` runs several worker
// "lanes" concurrently *per candidate session*, not just one. Before this
// change, each peer session could have at most one `fetch_block` request
// outstanding at a time — the request round-trip (bounded by real network
// RTT, not local CPU) was fully serialized per peer, so a single
// high-latency peer trickled blocks in one at a time no matter how many
// blocks it actually held. `PeerSyncSession::fetch_block` already supports
// several concurrent in-flight requests to the *same* peer correctly
// (`pending_block_requests` is keyed by hash with a waiter list per hash,
// with a multi-waiter design) — nothing about the session itself required
// this one-at-a-time pattern, it was purely an artifact of spawning
// exactly one worker task per candidate here. Running several lanes per
// candidate lets that same session pipeline multiple outstanding
// `BlockRequest`s, amortizing RTT across the window instead of paying it
// once per block. `BlockWorkQueue::pop_for`/`mark_not_found`/
// `mark_timed_out`/`resolve_fetched` are all keyed per popped block, not
// per worker, so multiple lanes sharing one `peer_id` need no changes
// there: each lane only ever resolves the specific block it itself popped.
// `PeerSyncSession` seeds a new session's controller at this same value
// (`ADAPTIVE_WINDOW_INITIAL`), so day-one behavior for an unobserved peer
// is unchanged; it only diverges once real conditions are observed. See
// `fetch_blocks_from_sessions`'s lane-spawning loop below for the actual
// call site.

/// Shared, mutex-guarded work queue for multi-session block dispatch
/// tracking which blocks remain to fetch and, per block, which
/// candidate peer device ids have already tried and failed to provide it —
/// so a not-found response reassigns the block to a different candidate
/// instead of giving up, and a block every candidate has tried is
/// correctly recognized as exhausted rather than retried forever.
struct BlockWorkQueue {
    queue: VecDeque<BlockInfo>,
    tried_by: HashMap<Vec<u8>, HashSet<String>>,
    /// Blocks every candidate has tried and failed to provide — tracked
    /// separately from `queue` (which only ever holds work still worth
    /// attempting), so `remaining` can report them as still-missing
    /// instead of them silently vanishing once dropped from `queue`.
    exhausted: Vec<BlockInfo>,
    /// Count of blocks currently checked out by a worker (returned from
    /// `pop_for`, not yet resolved via `mark_not_found` or
    /// `resolve_fetched`) — a worker-starvation race found alongside
    /// `per_block_fetch_timeout`: `fetch_blocks_from_sessions`'s workers
    /// used to exit for good the first time `pop_for` came back empty. With
    /// a fast-failing peer that's harmless (a `mark_not_found` reassignment
    /// arrives within milliseconds, long before the other workers could
    /// plausibly have drained the queue and exited already). But
    /// `per_block_fetch_timeout` can leave a block checked out for several
    /// real seconds before a stuck request is finally treated as
    /// not-found and requeued — plenty of time for every *other* worker to
    /// finish its own share, see an empty queue, and exit permanently.
    /// Once every worker has exited, the block that finally gets requeued
    /// has no one left to claim it, and `fetch_blocks_from_sessions`
    /// wrongly reports it as still-missing even though another,
    /// already-idle candidate never got a real chance at it (reproduced by
    /// `yadorilink-daemon/tests/multi_peer_hydration.rs`). While `outstanding`
    /// is nonzero, an idle worker must keep polling instead of exiting,
    /// since resolving that outstanding block might put more work back in
    /// `queue`; only once it reaches zero (nothing left in flight anywhere)
    /// is an empty `queue` actually final.
    outstanding: usize,
    /// `(block hash, peer_id) -> (not eligible again until, consecutive
    /// timeout count)`, populated by `mark_timed_out`. A timeout is
    /// ambiguous (the peer might genuinely have the block and just be
    /// slow/busy right now — see `mark_timed_out`'s own doc comment), so
    /// unlike `mark_not_found` it must not stop retrying that peer. But
    /// without *some* delay, `pop_for` lets the very next lane re-pop the
    /// identical block for the identical peer with zero cooldown — if the
    /// timeout happened because that peer's own read/hash/compress queue
    /// is backed up (several peers requesting the same hot block at once
    /// is the common case, not a single stuck request), an immediate
    /// retry lands on the same congestion and can time out again, and a
    /// pile of lanes doing this at once amplifies the very congestion
    /// that caused the first timeout instead of giving it a chance to
    /// drain. This is jittered exponential backoff *per (block, peer)
    /// pair*, not a broad session-level penalty: a different peer (or
    /// this same peer for a different block) is never held back by it.
    timeout_backoff: HashMap<(Vec<u8>, String), (tokio::time::Instant, u32)>,
    /// Blocks some candidate failed to supply WITHOUT saying it does not
    /// hold them: a timeout, a lost exchange, a refusal, a busy peer, bytes
    /// that did not match. An exhausted block outside this set was refused
    /// by every candidate with an explicit "I do not hold it" (see
    /// [`Self::declined_everywhere`]).
    ambiguous: HashSet<Vec<u8>>,
}

/// `mark_timed_out` backoff schedule: `TIMEOUT_BACKOFF_BASE * 2^(n-1)`
/// (n = consecutive timeouts so far for this (block, peer) pair), capped at
/// `TIMEOUT_BACKOFF_CAP`, with the same +/-25% jitter shape as
/// `yadorilink_peer_session::peer_session`'s `RECONCILE_RETRY_JITTER_FRACTION`/
/// `NOT_FOUND_RETRY_JITTER_FRACTION` (avoids every lane waiting on the same
/// peer synchronizing their retries right back onto it at once). 1s/2s/4s/
/// capped-at-8s keeps the *first* retry fast (a single slow response is
/// still common and shouldn't be penalized much) while meaningfully spacing
/// out repeated hits on a peer that keeps timing out.
const TIMEOUT_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(1);
const TIMEOUT_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(8);
const TIMEOUT_BACKOFF_JITTER_FRACTION: f64 = 0.25;

fn timeout_backoff_delay(consecutive_timeouts: u32) -> std::time::Duration {
    let scale = 1u64 << consecutive_timeouts.saturating_sub(1).min(20);
    let backed_off = TIMEOUT_BACKOFF_BASE.saturating_mul(scale as u32).min(TIMEOUT_BACKOFF_CAP);
    let jitter =
        rand::random_range(-TIMEOUT_BACKOFF_JITTER_FRACTION..=TIMEOUT_BACKOFF_JITTER_FRACTION);
    backed_off.mul_f64((1.0 + jitter).max(0.0))
}

impl BlockWorkQueue {
    fn new(blocks: Vec<BlockInfo>) -> Self {
        Self {
            queue: blocks.into(),
            tried_by: HashMap::new(),
            exhausted: Vec::new(),
            outstanding: 0,
            timeout_backoff: HashMap::new(),
            ambiguous: HashSet::new(),
        }
    }

    /// Pops a block `peer_id` hasn't tried yet and isn't currently cooling
    /// down on (see `timeout_backoff`), cycling past (but not discarding)
    /// ones it has — those stay queued for another worker. `None` if this
    /// worker has no eligible work available right now. Every `Some`
    /// returned here must eventually be paired with exactly one of
    /// `mark_not_found`/`mark_timed_out`/`resolve_fetched`, which keeps
    /// `outstanding` (see its doc comment) accurate.
    fn pop_for(&mut self, peer_id: &str) -> Option<BlockInfo> {
        let now = tokio::time::Instant::now();
        let len = self.queue.len();
        for _ in 0..len {
            let block = self.queue.pop_front()?;
            let already_tried =
                self.tried_by.get(&block.hash).is_some_and(|tried| tried.contains(peer_id));
            if already_tried {
                self.queue.push_back(block);
                continue;
            }
            let cooling_down = self
                .timeout_backoff
                .get(&(block.hash.clone(), peer_id.to_string()))
                .is_some_and(|(not_before, _)| now < *not_before);
            if cooling_down {
                self.queue.push_back(block);
                continue;
            }
            self.outstanding += 1;
            return Some(block);
        }
        None
    }

    /// Whether any block popped via `pop_for` is still unresolved — see
    /// `outstanding`'s doc comment. Callers should keep polling rather than
    /// give up on an empty `queue` while this is true.
    fn has_outstanding(&self) -> bool {
        self.outstanding > 0
    }

    /// Whether any block currently in `queue` is only unavailable because
    /// of a not-yet-expired `timeout_backoff` cooldown (as opposed to
    /// every remaining candidate having genuinely never tried it, which
    /// `pop_for` would hand out immediately). Without this, every lane's
    /// `pop_for` returning `None` while a block is merely cooling down
    /// looks identical to the queue being truly empty — see
    /// `fetch_blocks_from_sessions`'s worker-exit check, which must treat
    /// this the same as `has_outstanding` and keep polling rather than
    /// exit early and report a still-recoverable block as missing.
    fn has_pending_backoff(&self) -> bool {
        let now = tokio::time::Instant::now();
        self.timeout_backoff.values().any(|(not_before, _)| now < *not_before)
    }

    /// Resolves a block `pop_for` returned as successfully fetched and
    /// stored — the counterpart to `mark_not_found` for the success path,
    /// which never re-touches `queue`/`tried_by` but must still release its
    /// `outstanding` slot (see that field's doc comment).
    fn resolve_fetched(&mut self) {
        self.outstanding -= 1;
    }

    /// Records that `peer_id` tried `block` and it wasn't there; requeues
    /// it unless every one of `all_candidates` has now tried it —
    /// genuinely unavailable from any currently-reachable peer, so it
    /// moves to `exhausted` (surfacing in `remaining`'s still-missing
    /// report) instead of being retried forever. Use this only for an
    /// unambiguous "not there" signal (an explicit not-found reply or a
    /// hash mismatch) — see
    /// `mark_timed_out` for a response that never arrived at all.
    fn mark_not_found(&mut self, block: BlockInfo, peer_id: &str, all_candidates: &[String]) {
        self.outstanding -= 1;
        let tried = self.tried_by.entry(block.hash.clone()).or_default();
        tried.insert(peer_id.to_string());
        if all_candidates.iter().all(|c| tried.contains(c)) {
            self.exhausted.push(block);
        } else {
            self.queue.push_back(block);
        }
    }

    /// Requeues `block` after `peer_id`'s request for it went
    /// unanswered within `per_block_fetch_timeout` — deliberately
    /// **not** recorded in `tried_by`, unlike `mark_not_found`. A
    /// timeout is ambiguous (the peer might genuinely have the block and
    /// just answered slowly, or the response was lost in transit — real,
    /// observed transport-layer message loss under concurrent-connection
    /// bursts, not just a theoretical concern) rather than a definitive
    /// "this peer doesn't have it." Treating a timeout the same as an
    /// explicit not-found (the original behavior) meant a block held by
    /// only *one* reachable candidate became permanently unrecoverable
    /// the moment that single candidate's response merely arrived late
    /// once — `exhausted` after exactly one `all_candidates.len == 1`
    /// timeout, with no other peer to reassign to and no path back to
    /// retrying the same one. Not marking `tried_by` here means the
    /// block is immediately eligible for *any* peer to pick up again,
    /// including the one that just timed out — still bounded overall by
    /// the outer file-level `HYDRATION_TIMEOUT`, which a peer stuck in a
    /// genuine timeout loop will eventually hit.
    fn mark_timed_out(&mut self, block: BlockInfo, peer_id: &str) {
        self.outstanding -= 1;
        self.ambiguous.insert(block.hash.clone());
        let key = (block.hash.clone(), peer_id.to_string());
        let consecutive_timeouts = self.timeout_backoff.get(&key).map_or(0, |(_, n)| *n) + 1;
        let not_before = tokio::time::Instant::now() + timeout_backoff_delay(consecutive_timeouts);
        self.timeout_backoff.insert(key, (not_before, consecutive_timeouts));
        self.queue.push_back(block);
    }

    /// Everything that ended up unfetched: work still queued (shouldn't
    /// normally happen once every worker has run out of untried blocks,
    /// but included for safety) plus everything exhausted.
    fn remaining(self) -> Vec<BlockInfo> {
        self.queue.into_iter().chain(self.exhausted).collect()
    }

    /// Records that `block`'s miss from `peer_id` was not an explicit "I do
    /// not hold it", then treats it like one for scheduling (the existing
    /// `mark_not_found` behaviour: move on to the next candidate).
    fn mark_no_answer(&mut self, block: BlockInfo, peer_id: &str, all_candidates: &[String]) {
        self.ambiguous.insert(block.hash.clone());
        self.mark_not_found(block, peer_id, all_candidates);
    }

    /// The exhausted blocks every candidate explicitly said it does not
    /// hold, with no other kind of miss from any of them.
    fn declined_everywhere(&self) -> HashSet<Vec<u8>> {
        self.exhausted
            .iter()
            .filter(|block| !self.ambiguous.contains(&block.hash))
            .map(|block| block.hash.clone())
            .collect()
    }

    /// Called only by `PoppedBlock::drop` when a worker died between
    /// `pop_for` and reaching one of `resolve_fetched`/`mark_not_found`/
    /// `mark_timed_out`. This crate's own `remaining()` only ever reports `queue`/`exhausted`, never
    /// `outstanding`, so a block a worker popped and then never resolved
    /// (a panic mid-flight, e.g. in `block_data_matches` or anywhere else
    /// in the worker's own loop body) would silently vanish from EVERY
    /// tracking set at once: not in `queue`, not `exhausted`, and
    /// `outstanding` never decremented back to let `has_outstanding`
    /// ever go false again either. The caller (`fetch_blocks_from_
    /// sessions`'s own caller) computes "successfully fetched" as
    /// `missing - remaining()`, so a vanished block would be silently
    /// counted as fetched and have its provenance recorded even though it
    /// was never actually written to the block store. Unlike
    /// `mark_not_found`, this must NOT record anything in `tried_by` (a
    /// worker panic is not evidence the peer lacks the block) and unlike
    /// `mark_timed_out`, it must NOT arm the peer's cooldown backoff
    /// either (same reasoning) -- it is a neutral "this attempt never
    /// actually happened" requeue, safe for any other worker (including
    /// the same peer) to immediately retry.
    fn requeue_after_worker_panic(&mut self, block: BlockInfo) {
        self.outstanding -= 1;
        self.queue.push_back(block);
    }
}

/// RAII wrapper around one block popped from a shared `BlockWorkQueue` via
/// `pop_for` -- see `BlockWorkQueue::requeue_after_worker_panic`'s own doc
/// comment for the exact bug this closes. Every `Some` `pop_for` returns
/// must eventually be resolved via exactly one of `resolve_fetched`/
/// `mark_not_found`/`mark_timed_out` (each consumes `self`, matching the
/// underlying `BlockWorkQueue` methods' own contract); if none of them
/// ever runs -- most notably because the worker task itself panicked
/// somewhere in between -- `Drop` requeues the block instead of leaving it
/// silently unaccounted for in every tracking set at once.
struct PoppedBlock {
    work: Arc<StdMutex<BlockWorkQueue>>,
    block: Option<BlockInfo>,
}

impl PoppedBlock {
    /// Pops one block for `peer_id` (if any is currently eligible) and
    /// reports, in the same lock acquisition the old inline
    /// `pop_for`-plus-pending-check code used, whether the caller should
    /// keep polling on a `None` rather than treat it as final -- see the
    /// call site's own comment for why `None` alone is not decisive.
    fn pop_for(work: &Arc<StdMutex<BlockWorkQueue>>, peer_id: &str) -> (Option<Self>, bool) {
        let mut q = work.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let popped = q.pop_for(peer_id);
        let still_pending = q.has_outstanding() || q.has_pending_backoff();
        (popped.map(|block| Self { work: work.clone(), block: Some(block) }), still_pending)
    }

    fn block(&self) -> &BlockInfo {
        self.block.as_ref().expect("PoppedBlock used after being resolved")
    }

    fn resolve_fetched(mut self) {
        self.block.take().expect("PoppedBlock resolved twice");
        self.work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).resolve_fetched();
    }

    fn mark_not_found(mut self, peer_id: &str, all_candidates: &[String]) {
        let block = self.block.take().expect("PoppedBlock resolved twice");
        self.work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).mark_not_found(
            block,
            peer_id,
            all_candidates,
        );
    }

    fn mark_no_answer(mut self, peer_id: &str, all_candidates: &[String]) {
        let block = self.block.take().expect("PoppedBlock resolved twice");
        self.work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).mark_no_answer(
            block,
            peer_id,
            all_candidates,
        );
    }

    fn mark_timed_out(mut self, peer_id: &str) {
        let block = self.block.take().expect("PoppedBlock resolved twice");
        self.work
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .mark_timed_out(block, peer_id);
    }
}

impl Drop for PoppedBlock {
    fn drop(&mut self) {
        if let Some(block) = self.block.take() {
            self.work
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .requeue_after_worker_panic(block);
        }
    }
}

/// Fetches `missing` by partitioning it across every session in
/// `candidates`, one worker task per session running concurrently.
/// A block a session reports not-found is reassigned to a
/// different candidate rather than abandoned. Fetched block data is
/// written to `block_store` as it arrives. Returns whatever couldn't be
/// fetched from *any* candidate — empty if everything was retrieved.
///
/// `progress` and `recent_errors` are the same lightweight, additive
/// observation hooks described in `crate::transfer_progress`/
/// `crate::recent_errors`'s own doc comments — this is the single choke
/// point every block fetch for a file already passes through, so it's
/// also where per-transfer progress, block-fetch latency, and a
/// block-integrity mismatch are recorded, without otherwise changing this
/// dispatcher's existing rate-limit/adaptive-window/reassignment behavior.
#[derive(Debug)]
enum BlockDispatchFatal {
    /// The peer supplied valid bytes, but this device could not persist them.
    /// This is a local storage failure and must never count against the peer.
    Storage(yadorilink_local_storage::StorageError),
    /// The block's bytes were durably persisted to the block store, but
    /// recording this group's provenance for it failed. Also local
    /// infrastructure, never a peer not-found signal — but fatal rather than
    /// silently skipped: a block resolved without its provenance durable
    /// would be indistinguishable from one that was never genuinely fetched
    /// through this group on the very next hydration attempt (see
    /// `resolve_blocks_local_first`'s `has_group_provenance` check).
    Provenance(yadorilink_sync_sqlite::SyncSqliteError),
    /// A local blocking/worker task failed before it could report a storage
    /// result. Also local infrastructure, never a peer not-found signal.
    WorkerTask(String),
}

impl BlockDispatchFatal {
    fn into_sync_error(self) -> SyncError {
        match self {
            Self::Storage(error) => SyncError::from(error),
            Self::Provenance(error) => SyncError::from(error),
            Self::WorkerTask(message) => SyncError::CorruptState(message),
        }
    }
}

fn record_dispatch_fatal(
    slot: &Arc<StdMutex<Option<BlockDispatchFatal>>>,
    error: BlockDispatchFatal,
) {
    let mut slot = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_none() {
        *slot = Some(error);
    }
}

fn dispatch_has_failed(slot: &Arc<StdMutex<Option<BlockDispatchFatal>>>) -> bool {
    slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_some()
}

#[allow(clippy::too_many_arguments)]
#[allow(
    clippy::too_many_lines,
    clippy::excessive_nesting,
    reason = "one block-fetch worker dispatch loop: the depth is the per-block outcome \
              decision tree (fetch timeout -> transport error -> not-found -> hash/size \
              verification -> block-store put -> group-provenance write), and every arm \
              decides the fate of the same `guard` work item (resolve / mark_not_found / \
              mark_timed_out / neutral requeue). Extracting a level would move that \
              guard's ownership across a function boundary and split the ordering the \
              provenance-before-resolve invariant depends on (see the inline comment on \
              `record_group_block_provenance`), which is exactly the bug this shape fixes."
)]
async fn fetch_blocks_from_sessions(
    group_id: &str,
    file_path: &str,
    missing: Vec<BlockInfo>,
    candidates: &[(String, Arc<PeerSyncSession>)],
    block_store: Arc<dyn BlockStore + Send + Sync>,
    replica_coordinator: Arc<crate::replica_coordinator::ReplicaCoordinator>,
    progress: crate::transfer_progress::TransferProgressTracker,
    recent_errors: crate::recent_errors::RecentErrorLog,
    stall: Option<Arc<HydrationStallTracker>>,
    stop: LaneStop,
) -> Result<Dispatched, SyncError> {
    if missing.is_empty() || candidates.is_empty() {
        return Ok(Dispatched { remaining: missing, declined_everywhere: HashSet::new() });
    }
    // Dropping this call (a caller's deadline, or its own caller giving up)
    // stops the lanes instead of leaving them fetching for nobody. Each lane
    // then leaves through its normal exit, which drains the block writes it
    // has in flight, so nothing half-written is abandoned.
    let _stop_lanes_on_drop = StopOnDrop(stop.clone());

    let candidate_ids: Vec<String> = candidates.iter().map(|(id, _)| id.clone()).collect();
    let work = Arc::new(StdMutex::new(BlockWorkQueue::new(missing)));
    let fatal = Arc::new(StdMutex::new(None::<BlockDispatchFatal>));

    // Each pushed `tokio::spawn(..)` still runs as its own
    // independently-scheduled task exactly as `JoinSet` would; this only
    // replaces `JoinSet`'s "poll whichever join handle finishes first"
    // bookkeeping. Every worker is drained to completion below before this
    // returns, so there is no abort-on-drop difference to preserve.
    let mut workers: FuturesUnordered<tokio::task::JoinHandle<()>> = FuturesUnordered::new();
    // Several lanes per candidate, not one — see the comment
    // block above `BlockWorkQueue` for the rationale. The
    // lane count
    // itself is no longer a fixed constant: each session's own adaptive
    // window (`fetch_window`) decides how many lanes *that* candidate gets
    // this round, based on RTT/timeout signals observed on that session
    // across every hydration so far — a fast/healthy peer gets more
    // concurrent lanes, a slow/lossy one gets fewer, and neither can ever
    // exceed the fixed security ceiling `fetch_window` itself is clamped
    // to. Extra lanes beyond what a given candidate actually
    // has work for are harmless: `pop_for` returning `(None, false)`
    // (queue empty, nothing outstanding anywhere) makes an idle lane exit
    // immediately, same as before.
    for (peer_id, session) in candidates {
        for _lane in 0..session.fetch_window() {
            let work = work.clone();
            let block_store = block_store.clone();
            let replica_coordinator = replica_coordinator.clone();
            let peer_id = peer_id.clone();
            let session = session.clone();
            let candidate_ids = candidate_ids.clone();
            let group_id = group_id.to_string();
            let file_path = file_path.to_string();
            let progress = progress.clone();
            let recent_errors = recent_errors.clone();
            let fatal = fatal.clone();
            let stall = stall.clone();
            let mut stop_rx = stop.subscribe();
            let persist = BlockPersistContext {
                block_store: block_store.clone(),
                replica_coordinator: replica_coordinator.clone(),
                group_id: group_id.clone(),
                file_path: file_path.clone(),
                peer_id: peer_id.clone(),
                progress: progress.clone(),
                recent_errors: recent_errors.clone(),
                fatal: fatal.clone(),
                stall: stall.clone(),
            };
            workers.push(tokio::spawn(async move {
            // Durability tickets this lane has handed off but not yet
            // collected. Bounded on both counts for the same reason the
            // store bounds its own queue: a count bound is what binds for
            // tiny blocks, a byte bound for large ones, and without the
            // second a lane holding sixteen-megabyte blocks would pin
            // hundreds of megabytes.
            let mut in_flight = DurabilityPipeline::new();
            loop {
                if dispatch_has_failed(&fatal) || *stop_rx.borrow() {
                    break;
                }
                // `PoppedBlock::pop_for` takes its own lock, held only
                // long enough to pop and read the pending flags -- fully
                // released before any `.await` below (never hold a std
                // `Mutex` guard across an await). From here on, `guard`
                // itself is responsible for `block`'s accounting: every
                // exit from this loop iteration must consume it via
                // exactly one of `resolve_fetched`/`mark_not_found`/
                // `mark_timed_out`, or -- the case those three exist
                // alongside `Drop` to cover -- if this worker task panics
                // anywhere before doing so, `guard`'s own `Drop` requeues
                // the block instead of it silently vanishing from every
                // tracking set at once (see `BlockWorkQueue::requeue_
                // after_worker_panic`'s doc comment).
                let (popped, still_pending) = PoppedBlock::pop_for(&work, &peer_id);
                let guard = match (popped, still_pending) {
                    (Some(guard), _) => guard,
                    // Either another worker still has a block checked out
                    // (see `outstanding`'s doc comment) or a block is
                    // sitting in `queue` cooling down after a timeout (see
                    // `has_pending_backoff`'s doc comment) -- either way
                    // `pop_for` coming back `None` right now isn't
                    // necessarily final.
                    (None, true) => {
                        tokio::select! {
                            _ = tokio::time::sleep(WORKER_IDLE_POLL_INTERVAL) => {}
                            _ = stop_rx.wait_for(|stopped| *stopped) => {}
                        }
                        continue;
                    }
                    (None, false) => break, // queue empty, nothing outstanding or cooling down: truly done
                };
                let block = guard.block().clone();
                // Measured across the whole bounded attempt (success,
                // not-found, request error, or timeout alike) —
                // `yadorilink_block_fetch_seconds` is "how long a
                // block-fetch round trip took," not just the
                // successful-outcome subset.
                let fetch_started = std::time::Instant::now();
                let outcome = tokio::select! {
                    outcome = tokio::time::timeout(
                        per_block_fetch_timeout(block.size as u64),
                        session.fetch_block_answer(&group_id, &file_path, &block.hash, block.size as u64),
                    ) => outcome,
                    // Stopped mid-request: the request is abandoned (nothing
                    // of it was written) and `guard` requeues the block
                    // neutrally on drop.
                    _ = stop_rx.wait_for(|stopped| *stopped) => break,
                };
                progress.observe_block_fetch_seconds(fetch_started.elapsed().as_secs_f64());
                match outcome {
                    Ok(Ok(BlockFetchAnswer::Found(data))) => {
                        if !block_data_matches(&block, &data) {
                            tracing::warn!(
                                peer = %peer_id,
                                file_path = %file_path,
                                hash = %hex::encode(&block.hash),
                                "peer returned block data that did not match the expected hash/size"
                            );
                            recent_errors.record("block_integrity", "hydration");
                            guard.mark_no_answer(&peer_id, &candidate_ids);
                            continue;
                        }
                        let bytes = data.len() as u64;
                        // Receiver-side phase marker: this block's
                        // content has now fully arrived over the wire and
                        // passed hash/size verification, before it is
                        // handed to local storage for the durable commit
                        // below. Fires once per block (this loop's own
                        // granularity), not once per run -- a phase-log
                        // reader takes the EARLIEST occurrence in a pass as
                        // "first block begins receiving" and the LATEST as
                        // "last content byte received," the same "many
                        // occurrences, pick the meaningful ones" reading
                        // `phase_log.rs` already gives the source side's own
                        // repeated `T_watch` lines.
                        tracing::debug!(
                            "phase T_recv_block_received: a block's content fully arrived over \
                             the wire and passed verification"
                        );
                        // Handed to a ticket rather than awaited here.
                        // The lane's next fetch starts immediately, so a
                        // block's durability barrier overlaps the next
                        // block's network round trip instead of
                        // alternating with it -- and several blocks are in
                        // the store's queue at once, which is what lets one
                        // group commit cover them all.
                        in_flight.push(
                            bytes,
                            tokio::spawn(persist_fetched_block(persist.clone(), guard, data)),
                        );
                        if let Some(join_error) = in_flight.settle_to_bound().await {
                            record_dispatch_fatal(
                                &fatal,
                                BlockDispatchFatal::WorkerTask(format!(
                                    "local block-durability task failed while hydrating \
                                     {group_id}/{file_path}: {join_error}"
                                )),
                            );
                            break;
                        }
                    }
                    Ok(Ok(BlockFetchAnswer::DontHave)) => {
                        guard.mark_not_found(&peer_id, &candidate_ids);
                    }
                    Ok(Ok(BlockFetchAnswer::NoAnswer)) => {
                        guard.mark_no_answer(&peer_id, &candidate_ids);
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(
                            error = %error,
                            peer = %peer_id,
                            "block fetch request failed transiently; reassigning without recording peer not-found"
                        );
                        recent_errors.record("transport", "hydration");
                        // A request/transport failure says nothing about
                        // whether this peer has the block. Reuse the retryable
                        // backoff path rather than permanently adding it to
                        // `tried_by` and possibly exhausting all peers.
                        guard.mark_timed_out(&peer_id);
                    }
                    Err(_elapsed) => {
                        // See `per_block_fetch_timeout`'s doc comment: this
                        // peer never answered at all (as distinct from
                        // `Ok(Ok(None))`, an explicit not-found reply). Uses
                        // `mark_timed_out`, not `mark_not_found` — see that
                        // method's doc comment for why a mere timeout must
                        // not permanently write this peer off for this
                        // block, only reassign it (possibly back to the
                        // same peer) so one stuck/lost request can't make a
                        // block unrecoverable when it happens to be the
                        // only reachable holder.
                        //
                        // Also feeds this as a loss/timeout signal to the
                        // session's own adaptive window (`fetch_window`'s doc
                        // comment) — `fetch_block`'s future was dropped by
                        // this very `tokio::time::timeout` the instant it
                        // fired, so the session itself never got a chance
                        // to observe this outcome on its own; this is the
                        // one place that can tell it.
                        tracing::warn!(
                            peer = %peer_id,
                            size = block.size,
                            timeout = ?per_block_fetch_timeout(block.size as u64),
                            "block fetch timed out waiting for this peer's response; reassigning"
                        );
                        session.record_fetch_timeout();
                        guard.mark_timed_out(&peer_id);
                    }
                }
            }
            // Every exit from the loop above lands here, so no lane can
            // return while a block it fetched is still only half-committed.
            // That matters for more than tidiness: until a ticket resolves,
            // its block is still counted `outstanding`, which is what keeps
            // the other lanes from concluding the queue is finally empty.
            if let Some(join_error) = in_flight.settle_all().await {
                record_dispatch_fatal(
                    &fatal,
                    BlockDispatchFatal::WorkerTask(format!(
                        "local block-durability task failed while hydrating \
                         {group_id}/{file_path}: {join_error}"
                    )),
                );
            }
        }));
        }
    }
    while let Some(joined) = workers.next().await {
        if let Err(join_error) = joined {
            record_dispatch_fatal(
                &fatal,
                BlockDispatchFatal::WorkerTask(format!(
                    "hydration worker task failed before completing its local bookkeeping: {join_error}"
                )),
            );
        }
    }

    if let Some(error) = fatal.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take() {
        return Err(error.into_sync_error());
    }

    let work = Arc::into_inner(work)
        .expect("all worker tasks have completed, no other Arc clones remain")
        .into_inner()
        .unwrap();
    let declined_everywhere = work.declined_everywhere();
    Ok(Dispatched { remaining: work.remaining(), declined_everywhere })
}

/// What [`fetch_blocks_from_sessions`] could not fetch.
#[derive(Debug)]
struct Dispatched {
    /// Every block still not held: empty when everything was fetched.
    remaining: Vec<BlockInfo>,
    /// The subset of `remaining` every candidate explicitly said it does not
    /// hold, with no other kind of miss from any of them. Anything else in
    /// `remaining` went unanswered somewhere and says nothing about whether
    /// the content exists.
    declined_everywhere: HashSet<Vec<u8>>,
}

/// Tells a [`fetch_blocks_from_sessions`] call's lanes to stop taking new
/// work. A lane that sees it abandons its request in flight and leaves
/// through its normal exit, which waits for the block writes it already
/// started, so the call returns only once nothing of it is still running.
#[derive(Clone)]
struct LaneStop(Arc<tokio::sync::watch::Sender<bool>>);

impl LaneStop {
    fn new() -> Self {
        Self(Arc::new(tokio::sync::watch::Sender::new(false)))
    }

    fn stop(&self) {
        self.0.send_replace(true);
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.0.subscribe()
    }
}

struct StopOnDrop(LaneStop);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// How many fetched blocks one lane may have awaiting durability at once,
/// and how many of their bytes it may hold.
///
/// Both bounds, for the reason the block store needs both: a count binds
/// for tiny blocks and a byte budget for large ones. Eight is enough to
/// keep a lane's next fetch overlapping the previous block's barrier --
/// the thing this pipeline exists for -- without turning a lane into an
/// unbounded buffer.
const DURABILITY_PIPELINE_DEPTH: usize = 8;
const DURABILITY_PIPELINE_BYTES: u64 = 8 * 1024 * 1024;

/// One lane's outstanding durability tickets.
///
/// The lane hands a fetched block here and goes straight back to the
/// network; this is what keeps the previous block's durability barrier
/// overlapping the next block's round trip instead of alternating with it,
/// and what puts several blocks in the store's commit queue at once so one
/// group barrier can cover them all.
struct DurabilityPipeline {
    tickets: FuturesUnordered<tokio::task::JoinHandle<u64>>,
    bytes: u64,
}

impl DurabilityPipeline {
    fn new() -> Self {
        Self { tickets: FuturesUnordered::new(), bytes: 0 }
    }

    /// Adds a ticket for a block of `bytes`. Does not wait; the caller
    /// settles back to the bound separately, so a push never costs a
    /// barrier it did not have to pay.
    fn push(&mut self, bytes: u64, ticket: tokio::task::JoinHandle<u64>) {
        self.bytes += bytes;
        self.tickets.push(ticket);
    }

    /// Observability for this module's own tests -- the production path
    /// never asks, it just pushes and settles.
    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.tickets.len()
    }

    #[cfg(test)]
    fn in_flight_bytes(&self) -> u64 {
        self.bytes
    }

    /// Collects finished tickets until the pipeline is back inside both
    /// bounds. Returns the first join error seen, if any.
    async fn settle_to_bound(&mut self) -> Option<tokio::task::JoinError> {
        while self.tickets.len() >= DURABILITY_PIPELINE_DEPTH
            || self.bytes >= DURABILITY_PIPELINE_BYTES
        {
            match self.tickets.next().await {
                Some(Ok(done)) => self.bytes = self.bytes.saturating_sub(done),
                Some(Err(join_error)) => return Some(join_error),
                None => break,
            }
        }
        None
    }

    /// Collects every outstanding ticket. A lane must do this before it
    /// returns: until a ticket resolves, its block is still counted
    /// `outstanding`, which is what stops the other lanes concluding the
    /// queue is finally empty -- and a lane that returned early would leave
    /// a block half-committed with nobody left to finish it.
    async fn settle_all(&mut self) -> Option<tokio::task::JoinError> {
        let mut first_error = None;
        while let Some(joined) = self.tickets.next().await {
            match joined {
                Ok(done) => self.bytes = self.bytes.saturating_sub(done),
                Err(join_error) => first_error = first_error.or(Some(join_error)),
            }
        }
        first_error
    }
}

/// What a durability ticket needs to finish a fetched block once the lane
/// that fetched it has moved on.
#[derive(Clone)]
struct BlockPersistContext {
    block_store: Arc<dyn BlockStore + Send + Sync>,
    replica_coordinator: Arc<crate::replica_coordinator::ReplicaCoordinator>,
    group_id: String,
    file_path: String,
    peer_id: String,
    progress: crate::transfer_progress::TransferProgressTracker,
    recent_errors: crate::recent_errors::RecentErrorLog,
    fatal: Arc<StdMutex<Option<BlockDispatchFatal>>>,
    stall: Option<Arc<HydrationStallTracker>>,
}

/// Makes one fetched block durable, records this group's provenance for
/// it, and resolves its work item -- everything the block still owes after
/// its bytes have arrived and been verified.
///
/// Split out of the lane loop so the lane can hand it off and go straight
/// back to fetching. Before, a lane alternated strictly between waiting on
/// the network and waiting on a durability barrier, so the two never
/// overlapped and the store saw at most one submission per lane at a time
/// -- which meant a group commit could only ever be as wide as the *fetch*
/// window, a number chosen by the peer's round-trip behaviour and nothing
/// to do with storage.
///
/// Returns the block's byte count, which is how the lane knows what to
/// release from its in-flight budget.
///
/// The provenance write stays here, immediately after durability and
/// before the work item resolves -- deliberately not deferred to the end
/// of the dispatch. `hydrate` wraps the whole multi-block fetch in one
/// outer timeout, and a deadline drops these futures mid-flight; a
/// provenance write deferred to "after every block succeeds" would never
/// happen for blocks that were genuinely, durably fetched moments before
/// the drop, and the next attempt would re-fetch bytes it already had.
/// Generic over the payload rather than naming the peer session's own
/// buffer type, so this crate needs no dependency edge just to spell a
/// parameter. The bound is what a spawned task requires and nothing more.
async fn persist_fetched_block<D>(persist: BlockPersistContext, guard: PoppedBlock, data: D) -> u64
where
    D: AsRef<[u8]> + Send + 'static,
{
    let BlockPersistContext {
        block_store,
        replica_coordinator,
        group_id,
        file_path,
        peer_id,
        progress,
        recent_errors,
        fatal,
        stall,
    } = persist;
    let block = guard.block().clone();
    let data_len = data.as_ref().len() as u64;
    let bytes = data_len;

    // `BlockStore::put` is synchronous
    // `std::fs` I/O plus a full SHA-256 hash — move it
    // off this tokio worker thread so a big/slow write
    // doesn't stall every other task (other peers'
    // messages, other lanes' fetches) sharing it.
    let put_result = {
        let block_store = block_store.clone();
        // Offloads the synchronous `std::fs` + SHA-256 block
        // write onto Tokio's blocking pool so a big/slow write
        // can't stall this worker.
        {
            tokio::task::spawn_blocking(move || block_store.put(data.as_ref())).await
        }
    };
    match put_result {
        Ok(Ok(_)) => {
            // Receiver-side phase marker: this
            // block is now durably committed to local
            // storage (`BlockStore::put` above is
            // synchronous, fsync included; see
            // `fs_backend.rs`'s own commit path -- there
            // is no background durability worker on
            // this side the way the source-side
            // chunker's producer/durability split has
            // one). Same "many occurrences per pass,
            // earliest is first-durable, latest is
            // last-durable" reading as `T_recv_block_
            // received` above.
            tracing::debug!(
                "phase T_recv_block_durable: a block's durable local commit \
                     completed"
            );
            // Record this group's provenance for the block
            // IMMEDIATELY after its bytes are durably in
            // the block store, and before the work item is
            // resolved -- never batched until the whole
            // dispatch finishes. `hydrate`'s caller wraps
            // the entire multi-block fetch in one outer
            // `tokio::time::timeout`; a deadline there
            // drops this future mid-flight, and a
            // provenance write deferred to "after every
            // block succeeds" would never happen for
            // blocks that were genuinely, durably fetched
            // moments before the drop. The next hydration
            // attempt's `has_group_provenance` check
            // would then treat already-present, verified
            // bytes as still missing and re-fetch them
            // from scratch -- observed directly as a real
            // repro (`relay_failure_during_hydration`'s
            // recovery step re-transferring ~80% of a
            // payload on every retry, never converging).
            let provenance_result = {
                let replica_coordinator = replica_coordinator.clone();
                let group_id = group_id.clone();
                let hash = block.hash.clone();
                {
                    tokio::task::spawn_blocking(move || {
                        replica_coordinator
                            .record_block_provenance(&group_id, std::slice::from_ref(&hash))
                    })
                    .await
                }
            };
            match provenance_result {
                Ok(Ok(())) => {
                    // Counted as done only once the bytes
                    // are actually persisted locally AND
                    // this group's provenance for them is
                    // durable. Reported to the stall
                    // tracker at the same point -- this
                    // IS the durable-progress signal
                    // `HydrationStallTracker` exists to
                    // watch for.
                    if let Some(stall) = &stall {
                        stall.record_progress(data_len);
                    }
                    progress.record_block_done(&group_id, &file_path, data_len, &peer_id);
                    guard.resolve_fetched()
                }
                Ok(Err(error)) => {
                    tracing::error!(
                        error = %error,
                        peer = %peer_id,
                        file_path = %file_path,
                        "block bytes persisted but recording this group's \
                         provenance for it failed"
                    );
                    recent_errors.record("storage", "hydration_local_persist");
                    record_dispatch_fatal(&fatal, BlockDispatchFatal::Provenance(error));
                    // Dropping the guard neutrally requeues
                    // the block. It does NOT mark this
                    // peer as lacking it.
                    drop(guard);
                    return bytes;
                }
                Err(join_error) => {
                    tracing::error!(
                        error = %join_error,
                        peer = %peer_id,
                        file_path = %file_path,
                        "local provenance-write task failed"
                    );
                    recent_errors.record("corrupt_state", "hydration_local_persist");
                    record_dispatch_fatal(
                        &fatal,
                        BlockDispatchFatal::WorkerTask(format!(
                            "local provenance-write task failed while \
                                 hydrating {group_id}/{file_path}: {join_error}"
                        )),
                    );
                    drop(guard);
                    return bytes;
                }
            }
        }
        Ok(Err(error)) => {
            tracing::error!(
                error = %error,
                peer = %peer_id,
                file_path = %file_path,
                "peer supplied a valid block but local persistence failed"
            );
            recent_errors.record("storage", "hydration_local_persist");
            record_dispatch_fatal(&fatal, BlockDispatchFatal::Storage(error));
            // Dropping the guard neutrally requeues the block.
            // It does NOT mark this peer as lacking it.
            drop(guard);
            return bytes;
        }
        Err(join_error) => {
            tracing::error!(
                error = %join_error,
                peer = %peer_id,
                file_path = %file_path,
                "local block-store write task failed"
            );
            recent_errors.record("corrupt_state", "hydration_local_persist");
            record_dispatch_fatal(
                    &fatal,
                    BlockDispatchFatal::WorkerTask(format!(
                        "local block-store write task failed while hydrating {group_id}/{file_path}: {join_error}"
                    )),
                );
            drop(guard);
            return bytes;
        }
    }

    bytes
}

/// Hydrates `path` in `group_id` by partitioning its missing blocks across
/// every currently-connected, authorized peer session and fetching
/// concurrently, bounded by a stall deadline (`HydrationStallTracker`) that
/// starts at `HYDRATION_TIMEOUT` and grows to cover the largest missing
/// block's own real response deadline. Reverts to `Remote` and
/// returns `HydrationFailed` if no block durably completes for that whole
/// stall budget, or if any block remains unavailable from every candidate.
pub async fn hydrate(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
) -> Result<(), SyncError> {
    hydrate_impl(state, group_id, path, HydrationBound::Stall(HYDRATION_TIMEOUT)).await
}

/// Like `hydrate`, but `timeout` is an absolute wall-clock ceiling on the
/// whole dispatch, not a stall-tracker base -- this deliberately does NOT
/// get `HydrationStallTracker`'s size-aware extension. A caller reaching
/// for this function instead of `hydrate` is asking for a hard cap that
/// holds regardless of how large the missing blocks turn out to be (e.g. a
/// test proving the deadline mechanism actually bounds execution, or a
/// call site that would rather fail fast than wait out a large transfer);
/// `hydrate`'s own default path is what production code should use when it
/// wants slow-but-genuinely-progressing transfers to keep going past
/// `HYDRATION_TIMEOUT`.
pub async fn hydrate_with_timeout(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    timeout: std::time::Duration,
) -> Result<(), SyncError> {
    hydrate_impl(state, group_id, path, HydrationBound::Flat(timeout)).await
}

/// Where a materialization's bytes end up.
pub(crate) enum Sink<'a> {
    /// The file at its path under the link's directory: the existing write, with its disk
    /// admission, fence and proof (a `ProviderKind::None` root).
    InPlace,
    /// A temp file in the daemon's staging directory, assembled and verified; the OS takes it
    /// (a provider root, which has no daemon-visible directory).
    Temp(&'a crate::application::ports::TempMaterialization<'a>),
}

pub(crate) enum Materialized {
    InPlace,
    Temp(crate::application::ports::TempOutcome),
}

/// The one hydration primitive: make the CURRENT version of `path` available, into `sink`.
/// Both sinks run under the same version-bound guard and fetch the missing blocks the same way;
/// they differ only in what happens to the verified bytes.
pub(crate) async fn materialize_path(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    sink: Sink<'_>,
) -> Result<Materialized, SyncError> {
    match sink {
        Sink::InPlace => hydrate(state, group_id, path).await.map(|()| Materialized::InPlace),
        Sink::Temp(request) => {
            let stall = Arc::new(
                HydrationStallTracker::new(HYDRATION_TIMEOUT)
                    .with_progress(request.progress.clone()),
            );
            let outcome = run_with_stall_deadline(
                path,
                &stall,
                assemble_to_temp(state, group_id, path, request, Some(&stall)),
            )
            .await;
            if let Err(error) = &outcome {
                state.telemetry.record_recent_error(error.category(), "hydration");
            }
            outcome.map(Materialized::Temp)
        }
    }
}

/// The write intent of one in-place hydration: cleared when the attempt ends without having
/// reached the proof commit (nothing was published, so nothing is in flight any more), left open
/// by [`IntentScope::disarm`] when the commit cleared it itself or deliberately keeps it for the
/// retry, and left open when the process dies (nothing runs then, which is the point) or panics.
struct IntentScope<'a> {
    guard: Option<crate::materialization_intent::MaterializationIntentGuard<'a>>,
}

impl<'a> IntentScope<'a> {
    fn open(
        coordinator: &'a crate::replica_coordinator::ReplicaCoordinator,
        group_id: &'a str,
        path: &'a str,
        target: &[u8],
        permit: &'a yadorilink_root_authority::root_commit::RootCommitPermit<'a>,
    ) -> Result<Self, SyncError> {
        let guard = coordinator.open_hydration_write_intent(group_id, path, target, permit)?;
        Ok(Self { guard: Some(guard) })
    }

    fn disarm(&mut self) {
        self.guard = None;
    }
}

impl Drop for IntentScope<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        if let Some(guard) = self.guard.take() {
            if let Err(error) = guard.clear() {
                tracing::warn!(%error, "could not clear the write intent of an abandoned hydration");
            }
        }
    }
}

#[cfg(test)]
type SwapGapHook = Arc<dyn Fn() + Send + Sync>;

/// Test seam: destinations whose hydration fails right after the bytes were placed.
#[cfg(test)]
pub(crate) static FAIL_AFTER_PLACE: StdMutex<Option<HashSet<String>>> = StdMutex::new(None);

#[cfg(test)]
fn fail_after_place(out_path: &std::path::Path) -> bool {
    FAIL_AFTER_PLACE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .is_some_and(|set| set.contains(&out_path.display().to_string()))
}

/// Test seam: runs after the last local-edit check and right before the swap, to inject a write
/// into exactly that gap. Keyed by the absolute destination path (unique per test root).
#[cfg(test)]
pub(crate) static SWAP_GAP_HOOKS: StdMutex<Option<HashMap<String, SwapGapHook>>> =
    StdMutex::new(None);

#[cfg(test)]
fn swap_gap_hook(out_path: &std::path::Path) {
    let hook = SWAP_GAP_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .and_then(|hooks| hooks.get(&out_path.display().to_string()).cloned());
    if let Some(hook) = hook {
        hook();
    }
}

/// An assembled temp file that is removed unless it is handed back with [`StagedFile::keep`].
struct StagedFile(Option<std::path::PathBuf>);

impl StagedFile {
    fn new(path: std::path::PathBuf) -> Self {
        Self(Some(path))
    }

    fn path(&self) -> &std::path::Path {
        self.0.as_deref().unwrap_or_else(|| std::path::Path::new(""))
    }

    fn keep(mut self) -> std::path::PathBuf {
        self.0.take().unwrap_or_default()
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
pub(crate) type AssembledHookFn = Arc<
    dyn Fn(&std::path::Path) -> crate::application::ports::BoxFuture<'static, ()> + Send + Sync,
>;

/// Test seam: runs after an assembly was written and before it is verified and the version is
/// checked a last time,
/// to inject a concurrent commit, a corruption or a stall at exactly that point. Keyed by
/// `group/path` so concurrent tests do not see each other's hooks.
#[cfg(test)]
pub(crate) static ASSEMBLED_HOOKS: StdMutex<Option<HashMap<String, AssembledHookFn>>> =
    StdMutex::new(None);

#[cfg(test)]
async fn assembled_hook(group_id: &str, path: &str, assembled: &std::path::Path) {
    let hook = ASSEMBLED_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .and_then(|hooks| hooks.get(&format!("{group_id}/{path}")).cloned());
    if let Some(hook) = hook {
        hook(assembled).await;
    }
}

/// Writes `len` bytes of `source` from `skip` into a new file `out` and fsyncs it. `source` is
/// `None` only for an empty window. The caller's guard removes `out` when this fails.
fn cut_range(
    source: Option<&std::path::Path>,
    out: &std::path::Path,
    skip: u64,
    len: u64,
) -> Result<(), SyncError> {
    use std::io::{Read, Seek, SeekFrom};
    let io = |error: std::io::Error| SyncError::HydrationFailed(error.to_string());
    let mut target =
        std::fs::OpenOptions::new().write(true).create_new(true).open(out).map_err(io)?;
    if let Some(source) = source {
        let mut file = std::fs::File::open(source).map_err(io)?;
        file.seek(SeekFrom::Start(skip)).map_err(io)?;
        let copied = std::io::copy(&mut file.by_ref().take(len), &mut target).map_err(io)?;
        if copied != len {
            return Err(SyncError::CorruptState(
                "the verified window is shorter than its range".into(),
            ));
        }
    }
    target.sync_all().map_err(io)
}

/// Whether the file holds exactly `blocks`; each block that matched is reported to `observer`.
fn verify_assembled(
    path: &std::path::Path,
    blocks: &[BlockInfo],
    observer: Option<&(dyn Fn(u64) + Send + Sync)>,
) -> Result<bool, StorageError> {
    let comparison =
        yadorilink_local_storage::disk_content_comparison_observed(path, blocks, &|bytes| {
            if let Some(observer) = observer {
                observer(bytes);
            }
        })?;
    Ok(matches!(comparison, yadorilink_local_storage::DiskContentComparison::Matched))
}

/// The callback that adds written or verified bytes to `progress`, if there is one.
fn progress_observer(
    progress: Option<&Arc<crate::application::ports::AssemblyProgress>>,
) -> Option<Arc<dyn Fn(u64) + Send + Sync>> {
    progress.map(|progress| {
        let progress = progress.clone();
        Arc::new(move |bytes| progress.advance(bytes)) as Arc<dyn Fn(u64) + Send + Sync>
    })
}

/// How often an assembly starts over because the current version moved while it ran, before it
/// reports the version out of date.
const MAX_TEMP_RESTARTS: usize = 3;

/// The temp sink. Holds the path lock for the attempt (it serializes every attempt for the path,
/// so a second request finds the blocks local), binds the attempt to the version it reads under
/// the entry CAS, and returns bytes only if that version is still current after they were
/// assembled and verified. Nothing here commits a materialization state: the row returns to the
/// state it was in, and whether the OS holds the bytes is learned from the handoff and the
/// host's reports.
async fn assemble_to_temp(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    request: &crate::application::ports::TempMaterialization<'_>,
    stall: Option<&Arc<HydrationStallTracker>>,
) -> Result<crate::application::ports::TempOutcome, SyncError> {
    use crate::application::ports::{TempAssembly, TempOutcome};
    let _write_activity = state.begin_write_activity();
    let coordinator = state.replica_coordinator.as_ref();
    let path_lock = state.replica_coordinator.path_lock_registry().path_lock(group_id, path);
    let _path_guard = crate::receive_diag::lock_path(&path_lock).await;
    if coordinator.held_path_repository().group_frozen(group_id)? {
        return Err(SyncError::HydrationFailed(format!(
            "{group_id}/{path} is frozen by a rebootstrap"
        )));
    }
    let current_version =
        || -> Result<Option<yadorilink_replica_domain::ids::VersionHash>, SyncError> {
            Ok(coordinator
                .file_index_repository()
                .canonical_current_row(group_id, path)?
                .filter(|row| !row.snapshot.deleted)
                .map(|row| row.version_hash()))
        };
    for _ in 0..MAX_TEMP_RESTARTS {
        let Some(canonical) =
            coordinator.file_index_repository().canonical_current_row(group_id, path)?
        else {
            return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
        };
        if canonical.snapshot.deleted
            || canonical.snapshot.record_kind != yadorilink_replica_domain::file::RecordKind::File
        {
            return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
        }
        // Not the empty `version_seq = 0` scaffold a metadata step creates for a path it has not
        // received yet: that is no version of the file, and handing it over would be a
        // "successful" zero-byte file. The same requirement as the in-place path.
        if !coordinator.file_index_repository().has_real_current_row(group_id, path)? {
            return Err(SyncError::HydrationFailed(path.to_string()));
        }
        let target = canonical.version_hash();
        if request.requested_version.is_some_and(|wanted| wanted != target) {
            return Ok(TempOutcome::VersionOutOfDate);
        }
        let size = canonical.snapshot.size;
        // A ranged request works on the covering blocks only; everything below (the fetch from
        // peers, the per-block and assembled-bytes verification) is the whole-file code applied
        // to that shorter block list.
        let window = match request.range {
            None => None,
            Some(range) => match range_window::plan(&canonical.snapshot.blocks, size, range)? {
                Some(window) => Some(window),
                None => return Ok(TempOutcome::RangeNotSatisfiable),
            },
        };
        let blocks = match &window {
            Some(window) => window.blocks.clone(),
            None => canonical.snapshot.blocks.clone(),
        };
        if let Some(progress) = &request.progress {
            progress.begin(blocks.iter().map(|block| u64::from(block.size)).sum());
        }
        // The covering blocks and the window cut from them exist side by side while it is cut.
        let assembled_len = window
            .as_ref()
            .map_or(size, |window| window.window_len().saturating_add(window.served.len));
        let staging_dir =
            request.staging_file.parent().unwrap_or_else(|| std::path::Path::new("."));
        let headroom = if state.disk_headroom_enforcement_enabled() {
            let headroom_override =
                state.governance_config.load_or_default().headroom_override_bytes;
            Some(Arc::new(
                crate::local_convergence::reserve_volume_headroom(
                    staging_dir,
                    request.staging_file,
                    assembled_len,
                    headroom_override,
                )
                .map_err(SyncError::from)?,
            ))
        } else {
            None
        };
        // Bound to this version: the row is `Hydrating` for exactly as long as the attempt runs,
        // and goes back to what it was when the guard drops.
        let entry_state = coordinator
            .materialization_state_repository()
            .get_materialization_state(group_id, path)?;
        let Some(attempt) = coordinator.begin_hydration(group_id, path, entry_state, target)?
        else {
            return Err(SyncError::HydrationFailed(path.to_string()));
        };
        let still_missing =
            resolve_blocks_local_first(state, group_id, path, &blocks, stall).await?;
        if !still_missing.is_empty() {
            return Err(SyncError::HydrationFailed(path.to_string()));
        }
        if current_version()? != Some(target) {
            drop(attempt);
            if request.requested_version.is_some() {
                return Ok(TempOutcome::VersionOutOfDate);
            }
            continue;
        }
        // Assembled beside the staging file, fsynced, never visible to the extension. The
        // assembly removes its own temp file if this future is dropped (a cancel). A window of
        // no bytes needs no assembly at all.
        let assembled = if blocks.is_empty() && window.is_some() {
            None
        } else {
            Some(
                crate::local_convergence::types::reconstruct_file_to_temp_off_runtime_observed(
                    Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                        state.block_store.clone(),
                    )),
                    request.staging_file,
                    &blocks,
                    canonical.snapshot.mtime_unix_nanos,
                    // Kept here too: the reservation lasts until the window is cut.
                    headroom.clone(),
                    // A provider's staging directory is not a linked folder start recovers.
                    Arc::new(yadorilink_local_storage::NoTempLedger),
                    progress_observer(request.progress.as_ref()),
                )
                .await
                .map_err(|error| SyncError::HydrationFailed(format!("{path}: {error}")))?,
            )
        };
        // Removed again unless it is handed back: a cancel or an error leaves nothing in staging.
        let assembled = assembled.map(StagedFile::new);
        #[cfg(test)]
        if let Some(assembled) = &assembled {
            assembled_hook(group_id, path, assembled.path()).await;
        }
        if let Some(assembled) = &assembled {
            let verified = {
                let (assembled, blocks) = (assembled.path().to_path_buf(), blocks.clone());
                let observer = progress_observer(request.progress.as_ref());
                run_blocking_sweep_offloaded(move || {
                    verify_assembled(&assembled, &blocks, observer.as_deref())
                })
            };
            if !verified? {
                return Err(SyncError::CorruptState(format!(
                    "{path}: the assembled bytes do not match the version's blocks"
                )));
            }
        }
        // A range is cut out of the verified window only after the whole window verified.
        // `headroom` stays held through the cut.
        let assembled = match (&window, assembled) {
            (Some(window), window_file) => {
                let cut = StagedFile::new(request.staging_file.to_path_buf());
                let (source, out, skip, len) = (
                    window_file.as_ref().map(|file| file.path().to_path_buf()),
                    request.staging_file.to_path_buf(),
                    window.skip,
                    window.served.len,
                );
                run_blocking_sweep_offloaded(move || {
                    cut_range(source.as_deref(), &out, skip, len)
                })?;
                cut
            }
            (None, Some(whole)) => whole,
            (None, None) => unreachable!("a whole-file assembly always has a file"),
        };
        // The version may have moved while the bytes were assembled and verified: never hand
        // over bytes of a version that is no longer current.
        if current_version()? != Some(target) {
            drop(attempt);
            if request.requested_version.is_some() {
                return Ok(TempOutcome::VersionOutOfDate);
            }
            continue;
        }
        drop(attempt);
        return Ok(TempOutcome::Assembled(TempAssembly {
            assembled: assembled.keep(),
            version_hash: target,
            size,
            range: window.map(|window| window.served),
        }));
    }
    Ok(TempOutcome::VersionOutOfDate)
}

/// Proves the link root is still the adopted folder immediately before an
/// assembled temp file is renamed into it. The assembly takes time
/// proportional to the file, long enough for the volume under the root to go
/// away and leave a bare mountpoint; publishing then would put the file on the
/// parent filesystem. On a mismatch the temp file is discarded and nothing is
/// published.
fn verify_root_before_publish(
    state: &DaemonState,
    group_id: &str,
    root: &std::path::Path,
    tmp_path: &std::path::Path,
    temp_ledger: &dyn yadorilink_local_storage::TempFileLedger,
) -> Result<(), SyncError> {
    if let Err(error) = yadorilink_root_authority::root_identity::VerifiedRoot::verify(
        root,
        group_id,
        state.replica_coordinator.as_ref(),
    ) {
        yadorilink_local_storage::discard_temp_file(tmp_path, temp_ledger);
        return Err(error.into());
    }
    Ok(())
}

/// How `hydrate_impl` bounds a dispatch -- see `hydrate` and
/// `hydrate_with_timeout`'s own doc comments for when each applies.
enum HydrationBound {
    /// A stall-tracked budget seeded at `Duration` and grown to cover the
    /// largest missing block's own real response deadline; only resets on
    /// durable per-block progress, not on a fixed wall clock.
    Stall(std::time::Duration),
    /// A flat, absolute `tokio::time::timeout` -- exactly this module's
    /// pre-stall-tracker behavior, preserved verbatim for callers that want
    /// a genuine hard ceiling.
    Flat(std::time::Duration),
}

async fn hydrate_impl(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    bound: HydrationBound,
) -> Result<(), SyncError> {
    // A provider root hydrates nothing through the filesystem pipeline.
    crate::provider_gate::require_filesystem_root(&state.replica_coordinator, group_id)?;
    // Single-flight coalescing -- a concurrent caller for the SAME
    // path (two apps opening the same file at once, or a retried
    // FETCH_DATA callback racing the original) becomes a follower here
    // and simply awaits this round's eventual outcome instead of running
    // its own redundant peer fetch. See `hydration_single_flight`'s own
    // module doc for why this is layered outside `hydrate_inner`'s
    // per-path lock, not a replacement for it.
    let leader = match state.hydrate_single_flight.join(group_id, path) {
        crate::hydration_single_flight::Role::Follower(mut rx) => {
            return match rx.changed().await {
                Ok(()) => match *rx.borrow() {
                    Some(Ok(())) => Ok(()),
                    _ => Err(SyncError::HydrationFailed(path.to_string())),
                },
                // The leader's `Sender` was dropped without ever sending --
                // structurally unreachable (`Leader`'s own `Drop` always
                // sends), kept as a fail-closed fallback rather than a
                // `.unwrap()`.
                Err(_) => Err(SyncError::HydrationFailed(path.to_string())),
            };
        }
        crate::hydration_single_flight::Role::Leader(leader) => leader,
    };

    // `run_with_stall_deadline` (and, for `Flat`, `tokio::time::timeout`)
    // dropping the `hydrate_inner` future on deadline runs that future's
    // own local drop glue exactly like any other Rust value drop --
    // including `HydrationAttempt`'s version-bound revert-on-drop,
    // which by this point is the ONLY thing responsible for reverting a
    // still-`Hydrating` row back to `Remote`. This used to ALSO
    // blindly force `Remote` here, unconditionally, AFTER that drop
    // already ran -- if `hydrate_inner` had raced past the guard's own
    // `complete()` (a successful commit) just before the deadline fired,
    // this blind write would silently downgrade a row this same attempt
    // had just correctly finished hydrating. Letting the guard be the sole
    // authority (bound to the version captured before marking
    // `Hydrating`) means a completed commit, or a DIFFERENT concurrent
    // attempt's own legitimate `Hydrating` row, is never touched here.
    let result = match bound {
        HydrationBound::Stall(base) => {
            let stall = Arc::new(HydrationStallTracker::new(base));
            run_with_stall_deadline(
                path,
                &stall,
                hydrate_inner(state, group_id, path, Some(&stall)),
            )
            .await
        }
        HydrationBound::Flat(timeout) => {
            tokio::time::timeout(timeout, hydrate_inner(state, group_id, path, None))
                .await
                .unwrap_or_else(|_| Err(SyncError::HydrationFailed(path.to_string())))
        }
    };
    // Every hydration failure (disk pressure, no reachable candidate,
    // timed-out/incomplete fetch, or anything else `hydrate_inner` can
    // return) lands in the recent-error ring buffer here, centrally —
    // `SyncError::category`'s doc comment for why this is safe to record
    // unconditionally (never derived from `Display`, so never a
    // path/volume/hash). Only the leader's own attempt is recorded --
    // followers observe the same underlying failure, not a distinct one.
    if let Err(e) = &result {
        state.telemetry.record_recent_error(e.category(), "hydration");
    }
    leader.complete(result.as_ref().map(|_| ()).map_err(|_| ()));
    result
}

#[allow(
    clippy::too_many_lines,
    reason = "one on-access hydration attempt as a single ordered sequence whose steps \
              share the attempt's locks, fences and timer; the inline comments justify \
              that ordering step by step"
)]
async fn hydrate_inner(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    stall: Option<&Arc<HydrationStallTracker>>,
) -> Result<(), SyncError> {
    // Hydration is a materialization write (block-store reads plus a
    // `reconstruct_file` disk write) — held for this whole function's
    // duration so an update install never starts mid-hydration.
    let _write_activity = state.begin_write_activity();
    let Some(initial_record) =
        state.replica_coordinator.file_index_repository().get_file(group_id, path)?
    else {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    };
    if initial_record.deleted {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    }
    let root_lease = state.root_lease_for(group_id)?;
    let root_op = root_lease.begin_operation()?;
    let root_commit_permit = root_op.permit();

    let root = local_root_for_group(state, group_id)?;

    // Disk-space preflight before hydration starts fetching anything at
    // all, scoped to the volume hosting this link's local folder —
    // checked before setting `Hydrating` (a link that's about to fail
    // preflight shouldn't announce "hydrating" to a concurrent status
    // query first) and before any peer is contacted, so disk pressure
    // never wastes a network round trip. A no-op fast path when the
    // daemon hasn't opted into headroom
    // enforcement at all — see
    // `DaemonState::disk_headroom_enforcement_enabled`'s doc comment for
    // why that's not just always-on (this same function is exercised
    // directly by several daemon integration tests that write real
    // content, e.g. `multi_peer_hydration.rs`).
    // The reservation is held until this function returns, through every write
    // below (they run on this task, so nothing can outlive it).
    let _headroom = if state.disk_headroom_enforcement_enabled() {
        let headroom_override = state.governance_config.load_or_default().headroom_override_bytes;
        Some(preflight_disk_pressure(state, path, &root, initial_record.size, headroom_override)?)
    } else {
        None
    };

    let out_path = root.join(path);
    let path_lock = state.replica_coordinator.path_lock_registry().path_lock(group_id, path);
    // Held for this whole function's remaining duration, including the
    // block fetch below -- NOT released and reacquired around it.
    let _path_guard = crate::receive_diag::lock_path(&path_lock).await;
    // A held path still carries what the row placed, or an uncaptured edit
    // of it; writing the row's version here would destroy that unexamined.
    // Its reconciliation places the row and releases it, under this same
    // lock.
    if state.replica_coordinator.held_path_repository().is_held(group_id, path)? {
        return Err(SyncError::HydrationFailed(format!(
            "{group_id}/{path} awaits reconciliation of its disk state"
        )));
    }
    // A group a rebootstrap freezes is not written until the rebootstrap finishes.
    if state.replica_coordinator.held_path_repository().group_frozen(group_id)? {
        return Err(SyncError::HydrationFailed(format!(
            "{group_id}/{path} is frozen by a rebootstrap"
        )));
    }
    // ONE read of the current row, under the lock, for everything this
    // attempt is about to put on disk and everything its proof will
    // name: the blocks and mtime `reconstruct_file` writes, the mode and
    // xattrs applied after it, the version the proof claims, the kind
    // this lane is allowed to touch, and the version the commit CAS is
    // guarded on.
    //
    // This used to be several separate reads spread across the function --
    // `get_file` here, `get_record_kind` below it, and
    // `get_current_version_record` after the fast path, and then `get_unix_mode`/`get_xattrs` on the far
    // side of a block fetch that can take seconds. The path lock does not
    // make that safe: native admission does not take it, so a
    // supersession can land between any two of them. The bytes then came
    // from one incarnation and the mode, the xattrs and the proof's
    // version from others -- a proof about a state that was never
    // assembled anywhere.
    let Some(canonical) =
        state.replica_coordinator.file_index_repository().canonical_current_row(group_id, path)?
    else {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    };
    // The exact version this attempt is about to put on disk. The proof
    // published at the end of this function has to name it:
    // `resolved_path_state_hash` encodes version PRESENCE, so a
    // versionless proof matches no desired resolution at all. It can
    // never settle this path, and the convergence engine re-materializes
    // it forever.
    let target_version = canonical.version_hash();
    let current = yadorilink_replica_domain::file::FileRecord {
        path: path.to_string(),
        size: canonical.snapshot.size,
        mtime_unix_nanos: canonical.snapshot.mtime_unix_nanos,
        blocks: canonical.snapshot.blocks.clone(),
        deleted: canonical.snapshot.deleted,
    };
    if current.deleted || current != initial_record {
        return Err(SyncError::HydrationFailed(path.to_string()));
    }
    // `get_file`/`list_files` cannot by themselves
    // distinguish a real, content-bearing current row from
    // a `version_seq == 0` bootstrap
    // scaffold row (a database from an earlier receive path can hold one) (`file_index.rs::ensure_bootstrap_row_for_metadata`)
    // -- a deliberate, documented placeholder (`size: 0, blocks: [],
    // deleted: false`) written for a newly-admitted path BEFORE
    // `materialize`/`materialize_dag_content_head` has run at all, meant
    // to be superseded the moment real content lands. `has_real_current_
    // row`'s own doc comment already names this exact hazard. A restart
    // landing in the (usually brief) window between the scaffold write
    // and the real projection leaves this scaffold stranded -- hydrating
    // it would reconstruct a genuinely-correct-for-THAT-record zero-byte
    // file (its `blocks` is legitimately empty), silently reporting
    // success for content that was simply never asked for yet. Fail closed and retriable instead:
    // this is exactly the shape `hydrate_with_retries`-style callers
    // already handle by design.
    if !state.replica_coordinator.file_index_repository().has_real_current_row(group_id, path)? {
        return Err(SyncError::HydrationFailed(path.to_string()));
    }
    // Only a regular `File` ever goes through the placeholder/hydrate
    // cycle at all -- a symlink or directory record is always eagerly
    // materialized in full the moment it's adopted
    // (`peer_session::materialize_symlink_at`), never left as a
    // blocks-empty `Remote` stand-in waiting for this function.
    // `hydrate` is reachable for an arbitrary caller-supplied path with
    // no upstream kind filtering (the shell IPC `HydrateRequest` handler
    // just resolves a path to a `(group_id, rel_path)` pair and calls
    // straight through — see `shell_ipc::handle_message`), so this
    // function must defend itself: falling through to `reconstruct_file`
    // below for a non-`File` kind would call it with this record's
    // `blocks` list (always empty for a symlink, since a symlink's
    // target is never chunked) and clobber the real on-disk symlink/
    // directory at `out_path` with an empty regular file. Nothing to
    // hydrate for a kind that is never a placeholder in the first place.
    if canonical.snapshot.record_kind != yadorilink_replica_domain::file::RecordKind::File {
        return Ok(());
    }
    // Sampled BEFORE anything reads or judges the file, and reused as
    // the baseline for every later decision about it.
    //
    // It used to be taken after the `Present` fast path below, which was
    // harmless while that path could only return. It is not harmless now
    // that it can fall through to a real reconstruct: the bytes would be
    // verified against the row at one instant and the overwrite guarded
    // against a baseline sampled at a later one, so a local application
    // editing the file in between would have its edit adopted as the
    // baseline and then overwritten. `path_lock` does not serialize an
    // external writer -- an editor writing to the file never takes it.
    let initial_lstat = std::fs::symlink_metadata(&out_path).ok();
    let initial_disk_identity = initial_lstat.as_ref().map(disk_identity_of);
    // Idempotent fast path: `hydrate` must be safe to call on a path that is
    // already materialized. Its only production caller (the shell IPC
    // `HydrateRequest` handler) tracks no per-path hydration state and has no
    // way to avoid asking for one that is already `Present`.
    //
    // Earlier versions of this check tried to decide from the filesystem
    // alone -- a size check, then size+mtime -- and each closed one failure
    // while reopening the other: an empty leftover artifact from an
    // interrupted materialization and a local edit truncated to zero bytes
    // are the same stateless observation. The discriminator has to be whether
    // THIS device ever verifiably wrote real content here, which is exactly
    // what the actual-state generation records.
    // Kept as the `Option` the column really is: the CAS below is exact
    // in both directions, so collapsing NULL to `Remote` here would
    // make it demand a value the row does not have.
    let entry_materialization_state = state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(group_id, path)?;
    // `Present` says only that an object exists at the path. Whether this
    // device wrote it is what an actual-state generation records, and
    // `dag_lookup_materialized_generation` is fail-closed: it returns the row
    // only while the fence it was published under is still current, and
    // cannot tell a caller "absent" from "stale". A `Present` row with no
    // usable generation holds an object nothing vouches for (a newer version
    // admitted over bytes whose proof a later write retired, or a user's
    // edit): it takes the admission below, which replaces such an object
    // only when it is already exactly the version the row names.
    let admit_start = || {
        run_blocking_sweep_offloaded(|| {
            state.replica_coordinator.admit_hydration_start(
                group_id,
                path,
                &out_path,
                initial_lstat.as_ref(),
                &current,
                canonical.snapshot.unix_mode,
                &canonical.snapshot.xattrs,
                &root_commit_permit,
            )
        })
    };
    let proof_vouches = entry_materialization_state == Some(MaterializationState::Present)
        && state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(group_id, path)?
            .is_some();
    if proof_vouches {
        // A usable proof is this device's own evidence that it wrote real
        // content here. Whatever is on disk NOW -- still that write, a local
        // edit of any kind including a truncate to zero, or even a local
        // delete -- is for the watcher and the dirty-path journal to notice
        // and adopt, not for `hydrate` to second-guess. So this returns
        // without touching the path, exactly as the fingerprint shortcut it
        // replaces did.
        //
        // A proof's existence is not the whole question, though. It was
        // published for ONE version, and a path moves on: an admission
        // supersedes the row without touching the mutation fence, so a
        // proof about the previous version stays usable while describing
        // content the row no longer names. Answering "already hydrated"
        // on that would report success for content this device does not
        // have -- and it is what `pin` delegates to, so tightening `pin`
        // alone left the gap exactly where it was.
        if state
            .replica_coordinator
            .sqlite()
            .dag_usable_proof_names_current_version(group_id, path)?
        {
            return Ok(());
        }
        // A usable proof that names some OTHER version. The common way to
        // get here is a metadata-only version bump: a mode or xattr change
        // moves the version the row derives while leaving every byte
        // exactly right. So ask disk, under the path lock this function
        // already holds -- the same question repair's own healing arm
        // asks.
        let bytes_match = disk_bytes_match_indexed_blocks(&out_path, &current.blocks)?;
        if !bytes_match {
            // The bytes are not the ones the row names, and the proof that
            // stands names another version: either an older write of this
            // device's own, untouched since (replaced below: this is a newer
            // version arriving over existing bytes), or an edit nobody has
            // journalled yet. Admission tells them apart by evidence and, for
            // the second, journals the edit and refuses -- reconstructing
            // over it would destroy it.
            if !admit_start()? {
                tracing::warn!(
                    %path,
                    "the file is neither the version the row names nor an untouched write of \
                     this device; leaving the local change for local capture and hydrating \
                     nothing"
                );
                return Err(SyncError::HydrationFailed(path.to_string()));
            }
        } else {
            // The bytes are not the whole claim. `target_version` is a hash
            // over the mode and the xattrs too, so re-proving on a byte
            // comparison alone publishes an `ExactObject` asserting a mode
            // and an xattr set nothing has checked -- and on the very case
            // this arm exists for, a metadata-only bump, those are precisely
            // the fields that moved. The old code did exactly that: it healed
            // the proof of a row whose recorded mode disk had never been
            // given, pairing a version whose hash bakes in the new mode with
            // a `FileIdentity` whose metadata fingerprint is over the old
            // one. Nothing downstream compares those two halves against each
            // other, so the contradiction was durable and invisible.
            // Everything below acts on what was just verified, so what was
            // verified has to still be there. A file that changed while the
            // bytes and the metadata were being read is not the file either
            // branch concluded anything about: healing would record the
            // identity of the changed file under the version of the old one,
            // and falling through would reconstruct over an edit nobody has
            // journalled yet.
            if disk_identity(&out_path)? != initial_disk_identity {
                return Err(SyncError::HydrationFailed(path.to_string()));
            }
            // The xattrs are compared with the strict reader: the best-effort
            // `xattrs_already_match_disk` reads a failed attribute read as "no
            // attributes", so it could heal a proof over attributes nothing
            // actually read. An attribute set that cannot be read is not a
            // match; it falls through to the write path below, as a mismatch
            // does, which reapplies the metadata and re-verifies it strictly.
            if yadorilink_local_storage::unix_mode_already_matches_disk(
                &out_path,
                canonical.snapshot.unix_mode,
            )? && matches!(
                yadorilink_local_storage::verify_replicated_xattrs_exact(
                    &out_path,
                    &canonical.snapshot.xattrs,
                ),
                Ok(true)
            ) {
                // Disk really does hold this version. Nothing is written;
                // this only restores the footing of a claim already true.
                let healed = heal_hydrated_proof_for_current_version(
                    state,
                    group_id,
                    path,
                    &out_path,
                    &target_version,
                    &root_commit_permit,
                )?;
                if healed {
                    return Ok(());
                }
                // The row moved again while we were checking. Fail closed:
                // whatever is current now is not what disk was compared
                // against.
                return Err(SyncError::CorruptState(format!(
                    "{path}: the row moved off the version its on-disk state was just verified \
                     against; publishing nothing"
                )));
            }
            // Right bytes, wrong metadata. Fall through to the ordinary write
            // path rather than healing or refusing. Its refusal to
            // reconstruct is about bytes, and the bytes have just been proven
            // to be the ones the row names -- under a disk identity the check
            // above requires to be unchanged since before they were read, so
            // the rewrite below cannot destroy an unjournalled local edit.
            // `hydration_commit_decision` then re-checks that same identity
            // once more immediately before the write.
            //
            // It is also the one path that applies this snapshot's mode and
            // xattrs and then proves what it actually wrote. Healing here
            // instead would be the cheaper lie, and refusing would wedge the
            // path: nothing else in the daemon repairs a metadata divergence
            // under a `Present` row.
        }
    }
    // Any other starting state: the file is supposed to be this device's
    // placeholder, and the attempt may only replace it if it still is. See
    // `admit_hydration_start`, which the convergence lane shares.
    else if !admit_start()? {
        tracing::warn!(
            %path,
            "the file is not one this device may replace; leaving the local change for local \
             capture and hydrating nothing"
        );
        return Err(SyncError::HydrationFailed(path.to_string()));
    }
    // `target_version` comes from the same read as the entry state -- see
    // `HydrationAttempt`'s own doc comment for why its revert-on-drop
    // must bind to the version instead of just the `Hydrating` state value.
    // A CAS, not a blind write -- same reason as the peer lane's own
    // entry. The path lock does not exclude a native-side supersession, so
    // an unconditional set can stamp `Hydrating` on a row that became V2
    // after this attempt read V1, and the V1-bound rollback guard will
    // then correctly decline to undo it, leaving V2 stuck `Hydrating`.
    // The observed state is part of the guard too: another attempt for
    // this same version may already have finished and stamped
    // `Present`.
    //
    // The guard it returns reverts to the state this attempt found the
    // row in. For the metadata-repair fallthrough that is `Present`, and
    // putting it back is what keeps the local-edit protection this lane
    // would otherwise have traded away.
    let Some(mut hydration_state) = state.replica_coordinator.begin_hydration(
        group_id,
        path,
        entry_materialization_state,
        target_version,
    )?
    else {
        return Err(SyncError::HydrationFailed(path.to_string()));
    };
    let record = current;

    // Local-present-first resolution (shared with `restore_to_version_inner`
    // via `resolve_blocks_local_first`): blocks already cached locally are
    // never fetched, so a placeholder whose blocks are all present and intact
    // hydrates with no peer contacted at all — i.e. it succeeds offline. A
    // peer is required only for genuinely-missing (or locally-corrupt) blocks.
    // `stall`: this dispatch's own stall tracker when `hydrate_impl` chose
    // `HydrationBound::Stall` -- `None` for `HydrationBound::Flat`, whose
    // caller wants a hard wall-clock ceiling instead (see `HydrationBound`'s
    // own doc comment). When present, its budget grows to cover the real
    // missing-block sizes once they're known, and every durably-completed
    // block resets it.
    let still_missing =
        resolve_blocks_local_first(state, group_id, path, &record.blocks, stall).await?;

    if !still_missing.is_empty() {
        return Err(SyncError::HydrationFailed(path.to_string()));
    }
    // Receiver-side phase marker: every block this file's record
    // lists is now present (already-local or freshly fetched-and-committed)
    // in this device's own block store. This is the file-level
    // completeness check, distinct from `T_recv_block_durable` above: on
    // this codebase's receiver path each block's own commit is already
    // synchronous (no batching, no background durability worker -- see
    // that tag's own comment), so this event and the LAST `T_recv_block_
    // durable` of the same pass are expected to land very close together,
    // not measure a genuinely separate "drain" phase the way the
    // source-side producer/durability split does.
    tracing::debug!("phase T_recv_all_blocks_available: every block this file needs is now local");

    // `hydration_commit_decision` is synchronous, and its `Present` arm
    // re-reads the whole file and re-hashes it against the indexed blocks
    // (`disk_bytes_match_indexed_blocks`) -- a full sequential read plus a
    // SHA-256 per block, unbounded in the file's size. Hand this worker's core
    // off for it rather than holding the runtime for the duration; see
    // `run_blocking_sweep_offloaded` for the guard's fallbacks.
    match run_blocking_sweep_offloaded(|| {
        hydration_commit_decision(
            state,
            group_id,
            path,
            &record,
            &root,
            &out_path,
            initial_disk_identity,
        )
    })? {
        HydrationCommitDecision::Commit => {
            // `hydration_commit_decision` above re-reads the link table
            // and compares `local_root_for_group` against `expected_root`,
            // but that only proves the group's CONFIGURED root path didn't
            // change -- it cannot detect an external volume being
            // unmounted and replaced by something else at the SAME
            // mountpoint path during the (possibly multi-second) block
            // fetch, which leaves that comparison trivially equal. This
            // MUST run before `verify_write_target_within_root` below, not
            // after: that call is not a pure check, it `create_dir_ all`s
            // `root` and `out_path`'s parent as a side effect --
            // calling it first would create directories on a
            // possibly-wrong replacement volume before its identity had
            // even been confirmed, defeating the point of re-verifying at
            // all.
            yadorilink_root_authority::root_identity::VerifiedRoot::verify(
                &root,
                group_id,
                state.replica_coordinator.as_ref(),
            )?;
            // `reconstruct_file` does no escape-checking of its own -- it is
            // always the caller's job (see its own doc comment). The
            // ordinary `peer_session::materialize`/`hydration::hydrate`
            // write paths already call `verify_write_target` before their
            // own `reconstruct_file`; this path did not, so an intermediate
            // directory symlink planted under `root` (a local actor, or a
            // TOCTOU race) could redirect this write outside the sync root
            // -- the write-side twin of the tombstone escape this module's
            // `verify_delete_target` closes on the delete side.
            yadorilink_local_storage::verify_write_target_within_root(
                &out_path,
                &root,
                &yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger::new(
                    state.replica_coordinator.as_ref(),
                    group_id,
                ),
            )?;
            // Synchronous, and proportional to the file: it reads every
            // block out of the block store and writes the assembled bytes to
            // disk. `hydrate` is called straight from async tasks, so hand
            // the worker's core off for the write instead of holding the
            // runtime for however long the file takes.
            //
            // Receiver-side phase marker: about to begin
            // reconstructing the real file from CAS blocks.
            // `run_blocking_sweep_offloaded` below is `block_in_place` (or,
            // outside a multi-thread runtime, a plain synchronous call), not
            // a queued `spawn_blocking`, so there is no meaningful dispatch
            // delay between this line and `reconstruct_file` actually
            // starting.
            tracing::debug!("phase T_recv_materialize_start: begins reconstructing the real file from CAS blocks");
            // This on-demand hydration write has no native-frontier proof of
            // its own to publish under -- it only ever bumps/invalidates
            // the fence, inside `path_lock` (held for this whole
            // function), before the real write below.
            //
            // The bumped value is this attempt's epoch, and everything it
            // publishes goes out under exactly that value. A racing mutator
            // that bumps again therefore makes this attempt LOSE, rather
            // than leaving a proof behind that vouches for bytes no longer
            // on disk.
            //
            // Past the bump the standing proof is stale, so the guard's
            // revert target becomes `Remote`: an abandoned attempt
            // must not restore a `Present` claim nothing can vouch for.
            // A durable write intent is opened BEFORE the fence bump and kept through the proof
            // commit (which clears it). A crash anywhere after the bump leaves the old bytes
            // under a stale proof; the open intent is what lets capture and repair read them as
            // the pre-image of an unfinished write instead of as a local edit.
            let mut intent = IntentScope::open(
                state.replica_coordinator.as_ref(),
                group_id,
                path,
                &yadorilink_local_storage::intent_target_hash(&record.blocks),
                &root_commit_permit,
            )?;
            let mutation_generation = hydration_state.begin_physical_write().map_err(|e| {
                SyncError::CorruptState(format!("{path}: mutation fence bump failed: {e}"))
            })?;
            // Assembled into a temp file first and published by rename only
            // after the local-edit guards are asked again. The commit
            // decision above is taken before the assemble, which reads and
            // fsyncs the whole file -- time proportional to its size. An
            // editor writing into the file during that time writes into
            // the inode the rename is about to replace, so a check that
            // only ran before the assemble let the rename discard the edit
            // and report `Present`. What stays unguarded is the gap
            // between this re-check and the rename itself, not the assemble.
            let temp_ledger = state.replica_coordinator.temp_ledger(group_id);
            let tmp_path = run_blocking_sweep_offloaded(|| {
                yadorilink_local_storage::reconstruct_file_to_temp_in(
                    &crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                        state.block_store.clone(),
                    ),
                    &out_path,
                    &record.blocks,
                    record.mtime_unix_nanos,
                    &temp_ledger,
                )
            })?;
            let untouched = (|| -> Result<bool, SyncError> {
                Ok(!journal_local_edit_seen_by_hydration(
                    state,
                    group_id,
                    path,
                    &out_path,
                    initial_disk_identity,
                    &root_commit_permit,
                )? && !state
                    .replica_coordinator
                    .dirty_path_repository()
                    .is_path_dirty(group_id, path)?)
            })();
            if !matches!(untouched, Ok(true)) {
                yadorilink_local_storage::discard_temp_file(&tmp_path, &temp_ledger);
                untouched?;
                tracing::warn!(
                    %path,
                    "the file changed on disk while its hydrated content was being assembled; \
                     leaving the local edit in place and publishing nothing"
                );
                return Err(SyncError::HydrationFailed(path.to_string()));
            }
            #[cfg(test)]
            swap_gap_hook(&out_path);
            // Placing the bytes is a replacing rename. A write that lands between the last check
            // above and this rename is not noticed; that window is a known limitation. The write
            // intent stays open from here on, through any failure, until an exact proof commits
            // (which clears it) or repair settles the path: clearing it would leave bytes under a
            // stale proof with nothing saying an unfinished write put them there.
            // A root that cannot be verified keeps the intent open like a failed placement: the
            // old bytes stand under a stale proof and the intent says an unfinished write put
            // them there.
            if let Err(error) =
                verify_root_before_publish(state, group_id, &root, &tmp_path, &temp_ledger)
            {
                intent.disarm();
                return Err(error);
            }
            let placed = run_blocking_sweep_offloaded(|| {
                yadorilink_local_storage::persist_reconstructed_file_in(
                    &tmp_path,
                    &out_path,
                    &temp_ledger,
                )
            });
            intent.disarm();
            placed?;
            #[cfg(test)]
            if fail_after_place(&out_path) {
                return Err(SyncError::HydrationFailed(path.to_string()));
            }
            // Metadata is part of the on-disk state the proof below
            // vouches for, so it has to land BEFORE that state is
            // observed. This used to run after the generation was already
            // published, which meant the recorded identity described the
            // file as it was before this same attempt set its own mode and
            // xattrs -- a proof of a state the attempt itself immediately
            // superseded.
            //
            // Without the mode call an executable file's exec bit was
            // silently lost on every daemon-side on-demand hydration: the
            // index kept the correct bit, but disk never got it applied
            // after `reconstruct_file`.
            //
            // Both come from the one row read this attempt took under the
            // path lock, not from a fresh read here. `target_version`
            // bakes the mode and the xattrs into its hash, so re-reading
            // them on this side of the block fetch would apply one
            // incarnation's metadata and then claim the other's version
            // for it -- and the exactness gate could not catch it,
            // because it verifies against the same row that supplied the
            // wrong value. If the row has moved, this write is stale, and
            // the commit below is where that is decided.
            //
            // The attributes are strictly confirmed inside this write, before
            // the final mode; without that confirmation there is no exact
            // proof to publish, even though the bytes and mode landed.
            let applied = yadorilink_local_storage::apply_file_metadata_verified(
                &out_path,
                canonical.snapshot.unix_mode,
                &canonical.snapshot.xattrs,
            )?;
            if let Err(refused) = yadorilink_local_storage::XattrEvidence::from(applied)
                .prove(&out_path, &canonical.snapshot.xattrs)
            {
                tracing::warn!(
                    %path,
                    ?refused,
                    "could not confirm the replicated extended attributes this hydration set; \
                     abandoning the attempt rather than publishing a proof they do not back"
                );
                return Err(SyncError::HydrationFailed(path.to_string()));
            }
            // The proof for the write this device just performed, observed
            // once the file is in its final state.
            //
            // A failed observation aborts the attempt rather than falling
            // through to the commit. The fence was already bumped above, so
            // any earlier proof for this path is stale -- claiming
            // `Present` here would leave exactly the claim-with-no-proof
            // that `hydration_commit_decision` refuses to reconstruct over,
            // wedging the path permanently. Returning instead drops
            // the access-hydration guard uncompleted, which reverts the row to
            // `Remote`, so a transient stat failure is retried rather
            // than fatal. This stays fail-closed even though the commit
            // primitive below accepts an optional identity: a hydration
            // that cannot see what it just wrote has nothing to vouch for.
            let identity =
                match yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path) {
                    Ok(identity) => identity,
                    Err(error) => {
                        tracing::warn!(
                            %path,
                            %error,
                            "could not observe the file just reconstructed; abandoning this \
                             hydration attempt rather than claiming Hydrated without a proof"
                        );
                        return Err(SyncError::HydrationFailed(path.to_string()));
                    }
                };
            // One durable transaction publishes the versioned proof, stamps
            // `Present`, and clears the materialization intent.
            //
            // The version guard is inside that same transaction rather
            // than a separate CAS afterwards: `hydration_commit_decision`
            // proved the row still matched a moment ago, but a concurrent
            // update can still land between that check and this commit even
            // while this `path_lock` acquisition is held. If the row has
            // moved on, the bytes this attempt just wrote are stale for
            // whatever version is current now, and nothing at all is
            // written -- including the still-open intent, which is the only
            // record that a write was ever in flight.
            //
            // The heads are derived inside the commit's own transaction:
            // reading them through a separate connection first costs this
            // hot path two extra pool round-trips, which is enough on its
            // own to miss a convergence deadline. `target_version` was read
            // at the top of this function, before the block fetch, which can
            // take seconds -- so it is a snapshot from an earlier
            // transaction exactly like repair's, and the guard's commit
            // checks it explicitly rather than assuming it.
            match hydration_state.commit_exact_file(
                identity,
                mutation_generation,
                &root_commit_permit,
            )? {
                InternalMaterializedCommit::Published(_) => intent.disarm(),
                InternalMaterializedCommit::FenceLost { live_mutation_generation } => {
                    intent.disarm();
                    tracing::warn!(
                        %path,
                        expected = mutation_generation,
                        live = ?live_mutation_generation,
                        "another mutator moved this path's fence while it was hydrating; \
                         publishing nothing and leaving the intent open for the retry"
                    );
                    return Err(SyncError::HydrationFailed(path.to_string()));
                }
                InternalMaterializedCommit::AuthoringSuperseded => {
                    intent.disarm();
                    tracing::warn!(
                        %path,
                        "this path's row moved while it was hydrating; the bytes \
                         just written are stale for the version that is current now"
                    );
                    return Err(SyncError::HydrationFailed(path.to_string()));
                }
            }
            // Receiver-side phase marker: the state-machine commit
            // that marks this file `Present` (fully materialized) has now
            // completed. The measured hydration window ends here; everything after this arm is bookkeeping
            // (clearing a degraded-link flag, single-flight completion).
            tracing::debug!(
                "phase T_recv_hydrated_commit: Hydrated state-machine commit completed"
            );
        }
        HydrationCommitDecision::AlreadyComplete => {}
        HydrationCommitDecision::Stale => {
            journal_local_edit_seen_by_hydration(
                state,
                group_id,
                path,
                &out_path,
                initial_disk_identity,
                &root_commit_permit,
            )?;
            return Err(SyncError::HydrationFailed(path.to_string()));
        }
    }
    hydration_state.complete();
    // A snappier recovery signal beyond the periodic backoff re-check
    // — any successful hydration on this link proves its
    // volume currently has headroom, so a stale Degraded entry (if any)
    // can clear immediately rather than waiting out the next scheduled
    // re-check. A no-op if the link wasn't degraded.
    state.clear_link_degraded(&root.to_string_lossy());
    Ok(())
}

/// Reserves `required_bytes` of the headroom of the volume hosting `root`
/// for a write of `path`, in the account every other write on that volume
/// shares. Fails cleanly with `SyncError::DiskPressure` (and marks the link
/// Degraded) if the write, with what other writes have reserved, would breach
/// the configured headroom. The space stays reserved until the returned guard
/// is dropped.
fn preflight_disk_pressure(
    state: &DaemonState,
    path: &str,
    root: &std::path::Path,
    required_bytes: u64,
    headroom_override: Option<u64>,
) -> Result<crate::local_convergence::HeadroomReservation, SyncError> {
    match crate::local_convergence::reserve_volume_headroom(
        root,
        &root.join(path),
        required_bytes,
        headroom_override,
    ) {
        Ok(reservation) => Ok(reservation),
        Err(yadorilink_local_storage::StorageError::DiskPressure {
            available_bytes,
            headroom_bytes,
            ..
        }) => {
            let err = SyncError::DiskPressure {
                path: root.join(path).display().to_string(),
                volume: root.display().to_string(),
                available_bytes,
                headroom_bytes,
            };
            state.mark_link_degraded(
                &root.to_string_lossy(),
                crate::link_registry::waiting_for_disk_space_reason(
                    &root.display().to_string(),
                    available_bytes,
                    headroom_bytes,
                ),
            );
            Err(err)
        }
        Err(other) => Err(other.into()),
    }
}

/// One file's current materialization state — a plain local index read, no
/// peer or path lock needed (unlike `hydrate`, this never changes
/// anything). `None` means the daemon has no
/// materialization-state row for `path` at all: never indexed, or not a
/// path this group currently tracks. Callers (the control-socket IPC
/// handler, `yadorilink status`-style tooling) must treat that as "not
/// currently known," never as an implicit `Remote`/`Present` guess.
pub fn materialization_status(
    state: &DaemonState,
    group_id: &str,
    path: &str,
) -> Result<Option<MaterializationStatusInfo>, SyncError> {
    let Some(materialization_state) = state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(group_id, path)?
    else {
        return Ok(None);
    };
    Ok(Some(MaterializationStatusInfo { state: materialization_state }))
}

/// [`materialization_status`]'s return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializationStatusInfo {
    pub state: MaterializationState,
}

/// The gate `evict` applies before anything else, shared with the shell menu so Free Up Space is
/// only offered where this passes.
///
/// This entry frees a file of a folder the daemon itself keeps on disk, and then leaves a
/// placeholder in its place. That is only safe where an operating-system placeholder provider
/// watches the result (the next open fetches the content again); an ordinary folder has none, so
/// freeing a file there would simply make it disappear. A provider folder (macOS File Provider)
/// is the only kind that can give space back, and it takes the provider eviction path instead
/// (`provider_evict`): this gate therefore refuses every ordinary folder, and says why.
pub(crate) fn evict_gate(state: &DaemonState, group_id: &str, path: &str) -> Result<(), SyncError> {
    crate::provider_gate::require_filesystem_root(&state.replica_coordinator, group_id)?;
    if !state.root_allows_on_demand(group_id) {
        return Err(SyncError::EvictionRejected(format!(
            "{path}: Free Up Space is only available for provider folders (File Provider on macOS); this is an \
             ordinary folder, where freeing a file would remove it from the folder"
        )));
    }
    Ok(())
}

/// Manually evicts `path` back to a placeholder (spec "Manual Eviction").
/// Resolves `group_id` to its local root path via the registered link.
///
/// Returns the REAL `EvictionOutcome`, not just success/failure
/// -- `evict_file` itself can return `Ok` while leaving the file fully
/// materialized (busy, not yet `Present`, or its on-disk
/// identity changed right before the commit; see `EvictionOutcome::
/// dehydrated`'s own doc comment), and this function used to collapse
/// that into a bare `Ok(())` indistinguishable from a real eviction.
/// Callers crossing the `application::ports` boundary (`DaemonMaterializationAdapter`)
/// translate this into that layer's own `EvictOutcome` DTO -- this
/// function itself stays in `yadorilink_filesystem_sync`'s vocabulary,
/// matching every other type this module already uses directly from that
/// crate.
pub fn evict(
    state: &DaemonState,
    group_id: &str,
    path: &str,
) -> Result<yadorilink_filesystem_sync::materialization_eviction::EvictionOutcome, SyncError> {
    evict_gate(state, group_id, path)?;
    let root = local_root_for_group(state, group_id)?;
    let is_full_replica = state.is_local_full_replica(group_id);
    let root_lease = state.root_lease_for(group_id)?;
    let root_op = root_lease.begin_operation()?;
    let root_commit_permit = root_op.permit();
    // See `gc::run_sweep_sync`'s comment: `state.block_store` is an
    // already-erased `Arc<dyn BlockStore + Send + Sync>`, so it needs the
    // adapter to reach `&dyn BlockReclamationStore`.
    let block_reclamation =
        crate::adapters::block_store_ports::BlockStorePortsAdapter::new(state.block_store.clone());
    evict_file(
        MaterializationContext {
            state: state.replica_coordinator.as_ref(),
            liveness_gate: state.block_liveness_gate(),
            store: &block_reclamation,
            root: &root,
            permit: &root_commit_permit,
        },
        group_id,
        path,
        is_full_replica,
        state,
    )
    .map_err(SyncError::from)
}

// --- restore engine ---

/// Resolves `version_seq`'s content — verifying local
/// presence of every block it references and, for any missing block,
/// attempting a peer fetch scoped to those hashes via the same
/// multi-session dispatch `hydrate` uses — and, on success, writes it to
/// disk and indexes it through the *ordinary* local-change path:
/// a brand-new current version, with the local device's version-
/// vector counter bumped and the change broadcast to peers exactly like
/// any other local edit. Never mutates or reorders any existing version
/// row; a concurrent edit racing this (adopted from a peer while this
/// runs) is caught by the same `SyncState::path_lock`-guarded read-
/// compare-write section `LocalChangeProcessor::process_event`/
/// `PeerSyncSession::reconcile_one_file` already use, so it resolves via
/// the existing version-vector conflict machinery with no restore-
/// specific special-casing.
///
/// Fails with `SyncError::VersionContentUnavailable` (never a generic I/O
/// or not-found error) and makes no index or on-disk change if some block
/// the version needs is missing locally and unavailable from every
/// currently-reachable, authorized peer within the timeout.
pub async fn restore_to_version(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    version_seq: i64,
) -> Result<(), SyncError> {
    restore_to_version_with_timeout(state, group_id, path, version_seq, HYDRATION_TIMEOUT).await
}

/// Like `restore_to_version`, with an explicit deadline — production
/// callers use the default (30s, matching `hydrate`'s own default); tests
/// use a much shorter one so the "no reachable peer" case doesn't make the
/// suite slow.
pub async fn restore_to_version_with_timeout(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    version_seq: i64,
    timeout: std::time::Duration,
) -> Result<(), SyncError> {
    tokio::time::timeout(timeout, restore_to_version_inner(state, group_id, path, version_seq))
        .await
        .unwrap_or_else(|_elapsed| {
            Err(SyncError::VersionContentUnavailable(format!("{group_id}/{path}@{version_seq}")))
        })
}

/// Writes the symlink a restore recreates, under the platform's own policy: Windows writes
/// nothing unless the group opted in to symlinks.
fn materialize_restored_symlink(
    state: &DaemonState,
    group_id: &str,
    out_path: &std::path::Path,
    target: &[u8],
) -> Result<(), SyncError> {
    #[cfg(unix)]
    {
        yadorilink_local_storage::materialize_symlink_in(
            out_path,
            target,
            &state.replica_coordinator.temp_ledger(group_id),
        )?;
    }
    #[cfg(windows)]
    {
        // Not opted in: writes nothing, same as `materialize_symlink_at`'s own policy skip.
        if state.replica_coordinator.link_repository().windows_symlink_opt_in_for_group(group_id)? {
            yadorilink_local_storage::materialize_symlink_windows_in(
                out_path,
                target,
                &state.replica_coordinator.temp_ledger(group_id),
            )?;
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (state, group_id, out_path, target);
    }
    Ok(())
}

async fn restore_to_version_inner(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    version_seq: i64,
) -> Result<(), SyncError> {
    restore_content_inner(state, group_id, path, RestoreSource::OwnVersion(version_seq))
        .await
        .map(|_placement| ())
}

/// What a guarded restore writes at its path: one of the path's own versions,
/// or a version of another path (a conflict copy's content taking the name it
/// came from).
pub(crate) enum RestoreSource<'a> {
    OwnVersion(i64),
    Content(&'a yadorilink_replica_domain::session_state::VersionRecord),
}

/// [`restore_to_version_with_timeout`] for any [`RestoreSource`], answering where the
/// namespace placed the content.
pub(crate) async fn restore_content_with_timeout(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    source: RestoreSource<'_>,
    timeout: std::time::Duration,
) -> Result<yadorilink_sync_sqlite::restore_operation::RestorePlacement, SyncError> {
    tokio::time::timeout(timeout, restore_content_inner(state, group_id, path, source))
        .await
        .unwrap_or_else(|_elapsed| {
            Err(SyncError::VersionContentUnavailable(format!("{group_id}/{path}")))
        })
}

#[allow(
    clippy::too_many_lines,
    reason = "one restore attempt as a single ordered sequence whose steps share the \
              same fence and permit; splitting it would separate each step from the \
              ordering argument written beside it"
)]
async fn restore_content_inner(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    source: RestoreSource<'_>,
) -> Result<yadorilink_sync_sqlite::restore_operation::RestorePlacement, SyncError> {
    // A materialization write (`reconstruct_file`) plus an index write,
    // same treatment as `hydrate_inner`'s guard above; also covers
    // `restore_trashed`, which calls through to this same function.
    let _write_activity = state.begin_write_activity();
    // Restore both reads the current record (to compute the new
    // version vector correctly) and writes new content — the exact same
    // read-compare-write shape `process_event`/`reconcile_one_file` are
    // already serialized against each other for, via this same lock. See
    // `SyncState::path_lock`'s doc comment for the race this closes.
    let path_lock = state.replica_coordinator.path_lock_registry().path_lock(group_id, path);
    let _guard = crate::receive_diag::lock_path(&path_lock).await;
    // A restore replaces what is on disk and authors the restored version, so it
    // is a write like any other: not in a group a rebootstrap freezes.
    if state.replica_coordinator.held_path_repository().group_frozen(group_id)? {
        return Err(SyncError::HydrationFailed(format!(
            "{group_id}/{path} is frozen by a rebootstrap"
        )));
    }
    // One root-authorized operation: this `LinkOperation` is held
    // from here -- before the journal/native write, the fence bump and the
    // physical write -- through the settle commit at the bottom, so a link
    // stop waits for the whole restore to drain instead of releasing the
    // root lock under a write still in flight. Every DB/native commit below
    // verifies this same operation's permit inside its own transaction, so
    // a root swapped at any point commits nothing on either root.
    let root_lease = state.root_lease_for(group_id)?;
    let root_op = root_lease.begin_operation()?;
    let root_commit_permit = root_op.permit();

    let version = match source {
        RestoreSource::OwnVersion(version_seq) => {
            let Some(version) = state.replica_coordinator.file_index_repository().get_version(
                group_id,
                path,
                version_seq,
            )?
            else {
                return Err(SyncError::NotFound(format!(
                    "version {version_seq} of {group_id}/{path}"
                )));
            };
            version
        }
        RestoreSource::Content(version) => version.clone(),
    };
    let version_seq = version.version_seq;
    if version.deleted {
        // A tombstone row itself carries no restorable content — the
        // caller wants `restore_trashed`, which resolves to the trashed
        // row's own `version_seq` (the last real content before the
        // delete), not this one.
        return Err(SyncError::NotFound(format!(
            "version {version_seq} of {group_id}/{path} is a deletion, not restorable content"
        )));
    }

    let root = local_root_for_group(state, group_id)?;
    let out_path = root.join(path);
    // What the path looked like before anything was fetched. The restore
    // replaces whatever is there, so it may only do so over the file this
    // baseline names; see `restore_would_destroy_local_state`.
    let initial_disk_identity = disk_identity(&out_path)?;

    // A version restore is the same kind of block-fetch transfer as an
    // ordinary hydration: it resolves the version's blocks through the exact
    // same local-present-first path (`resolve_blocks_local_first`), so a
    // version whose blocks are all still cached locally restores with no peer
    // contacted, and only genuinely-missing (or locally-corrupt) blocks are
    // fetched from a reachable peer. `None`: version restore keeps its own
    // flat `restore_to_version_with_timeout` deadline, out of scope for
    // the stall-based deadline `hydrate`/`hydrate_with_timeout` use.
    let still_missing =
        resolve_blocks_local_first(state, group_id, path, &version.blocks, None).await?;
    if !still_missing.is_empty() {
        let err = SyncError::VersionContentUnavailable(format!("{group_id}/{path}@{version_seq}"));
        state.telemetry.record_recent_error(err.category(), "restore_version");
        return Err(err);
    }

    let expected_current_version_seq = state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(group_id, path)?
        .into_iter()
        .find(|candidate| {
            candidate.state == yadorilink_replica_domain::session_state::VersionState::Current
        })
        .map(|candidate| candidate.version_seq);
    let now_unix_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let new_record = yadorilink_replica_domain::file::FileRecord {
        path: path.to_string(),
        size: version.size,
        mtime_unix_nanos: now_unix_nanos,
        blocks: version.blocks.clone(),
        deleted: false,
    };
    let restored_file_version = yadorilink_replica_domain::file::FileVersion::from_index_row(
        version.blocks.clone(),
        version.size,
        now_unix_nanos,
        version.record_kind,
        version.unix_mode,
        version.symlink_target.clone(),
        version.xattrs.clone(),
    );
    let emitter = state.local_author().ok_or_else(|| {
        SyncError::CorruptState(format!(
            "registered device {} has no author identity (no signing key, or its author \
             incarnation cannot be opened); refusing a restore with no native authoring",
            state.device_id
        ))
    })?;
    let operation_id = uuid::Uuid::new_v4().to_string();
    // Where the restored entry lands is the namespace's to decide, as for
    // any other change. When the tree changed shape since the version was
    // current -- its path now has to be a directory, an ancestor is a
    // synced file, or the path holds an object of the other shape --
    // writing it here would go over a directory, through a file, or fail
    // on what is in the way after the change was already live. The
    // ordinary projection its obligation drives places it instead (beside
    // the directory under its conflict-copy name, or below an ancestor it
    // turns into a directory, moving that file aside). The disk half of
    // that question is read here; the namespace half is asked inside the
    // same transaction that authors the change, which writes the journal
    // row only for a restore it writes itself -- so no crash can leave
    // startup recovery a row for a write that was never going to happen.
    let disk_allows_in_place =
        restore_disk_allows_in_place(state, group_id, path, &root, version.record_kind)?;
    // Before the journal row and the change it authors: a restore that has
    // to decline because of what is on disk must leave nothing behind.
    if disk_allows_in_place
        && restore_would_destroy_local_state(
            state,
            group_id,
            path,
            &out_path,
            initial_disk_identity,
            &version,
            &root_commit_permit,
        )?
    {
        return Err(SyncError::PathChangedLocally(format!("{group_id}/{path}")));
    }
    let placement = state.replica_coordinator.record_restore_placing(
        &yadorilink_replica_domain::session_state::RestoreOperation {
            operation_id: operation_id.clone(),
            group_id: group_id.to_string(),
            path: path.to_string(),
            target_version_seq: version_seq,
            expected_current_version_seq,
            state: yadorilink_replica_domain::session_state::RestoreOperationState::Prepared,
            record: new_record.clone(),
            origin_device_id: state.device_id.clone(),
            // Carried through to `commit_restore_operation`, which applies
            // it to the `current` row via the same atomic
            // `apply_local_meta_columns_in_tx` every other local content
            // emission uses -- restoring a symlink/executable version must
            // not just recreate the right bytes/link on disk (this
            // function's own record-kind dispatch below already does
            // that), the index's own classification of the path has to
            // move too, or a later caller trusting `record_kind` (like
            // `hydrate_inner`'s own kind guard) would still treat it as
            // whatever it was before the restore. `symlink_out_of_root` is
            // not carried by `VersionRecord` (a purely local, wire-only
            // classification computed from a live filesystem scan, not
            // versioned history) -- `false` is the same safe default used
            // at every other call site that constructs this without a
            // fresh scan to hand.
            meta: yadorilink_replica_domain::session_state::LocalFileMetaColumns {
                record_kind: version.record_kind,
                symlink_target: version.symlink_target.clone(),
                symlink_out_of_root: false,
                unix_mode: version.unix_mode,
                xattrs: version.xattrs.clone(),
            },
        },
        &restored_file_version,
        &emitter,
        &root_commit_permit,
        disk_allows_in_place,
    )?;
    if placement == yadorilink_sync_sqlite::restore_operation::RestorePlacement::Projection {
        drop(root_op);
        state.on_local_native_commit(group_id).await;
        return Ok(placement);
    }

    // The journal above is durable before the atomic replacement. Any error
    // from reconstruction is therefore ambiguous by design: leave the row for
    // startup reconciliation, which verifies the disk bytes before deciding
    // whether to commit or discard the intended index version.
    //
    // Two checks belong here, both mirroring `hydrate_inner`'s equivalent
    // guards for the identical shape of race (a block fetch above can take
    // several seconds, same as ordinary hydration):
    // - re-resolve the group's root fresh (`local_root_for_group` never
    //   caches) to catch an unlink/relink that happened during the fetch,
    //   rather than trusting the `root` captured before it;
    // - `verify_write_target_within_root` before `reconstruct_file`, which
    //   does no escape-checking of its own -- an intermediate directory
    //   symlink under `root` could otherwise redirect this write outside
    //   the sync root, same as `hydrate_inner`'s equivalent gap.
    if local_root_for_group(state, group_id).ok().as_deref() != Some(root.as_path()) {
        return Err(SyncError::HydrationFailed(path.to_string()));
    }
    // Re-resolving the link table's root path above only proves the
    // group's CONFIGURED root didn't change -- it cannot detect an
    // external volume being unmounted and replaced by something else at
    // the SAME mountpoint path during the fetch, which leaves that
    // comparison trivially equal. The same gap `hydrate_inner`'s own
    // `VerifiedRoot::verify` call closes for ordinary hydration.
    //
    // This MUST run before `verify_write_target_within_root` below, not
    // after: that call is not a pure check, it `create_dir_all`s `root`
    // and `out_path`'s parent as a side effect -- calling it first would create
    // directories on a possibly-wrong replacement volume before its
    // identity had even been confirmed.
    yadorilink_root_authority::root_identity::VerifiedRoot::verify(
        &root,
        group_id,
        state.replica_coordinator.as_ref(),
    )?;
    // And the operation's own lease, re-checked after the fetch and before
    // `verify_write_target_within_root` creates any directory: the root
    // this restore was admitted against must still be the one it writes
    // into. The settle below re-verifies it again inside its commit.
    root_commit_permit.verify()?;
    yadorilink_local_storage::verify_write_target_within_root(
        &out_path,
        &root,
        &yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger::new(
            state.replica_coordinator.as_ref(),
            group_id,
        ),
    )?;
    // Every mutation below (reconstruct_file, apply_unix_mode/
    // apply_xattrs, materialize_symlink, create_dir_all) runs under a
    // mutation-fence bump, like every sibling physical mutator in this
    // codebase (`hydrate_inner`'s equivalent write above,
    // `materialization_repair.rs`'s reconstruct path). Same reasoning as
    // `hydrate_inner`'s own bump: this restore write has no native-frontier
    // proof of its own to publish under (the local emission above creates
    // a fresh obligation for the ordinary scheduler to resolve later, but
    // THIS function's own direct write is not that resolution) -- it only
    // ever bumps/invalidates the fence, inside `path_lock` (held for this
    // whole function), before the real write below. Without this, an
    // existing `path_materialized_generations` proof for this path would
    // survive this write untouched, so a concurrent, unrelated completion
    // for the same path could read a proof as still "usable" (its
    // `published_under_mutation_generation` unchanged) right up to the
    // instant this restore silently changed the bytes it describes.
    //
    // The epoch is RETAINED, not discarded. It used to be bumped and
    // thrown away, and the index commit then went through the
    // external-adoption API, which mints a second epoch of its own on its
    // way to recording the write -- so this restore's own evidence could
    // never be published under the epoch its write actually happened in,
    // and carried no version either. Holding it here and CASing the commit
    // against it is what makes this an internal mutator like every other
    // physical writer: bump, write, publish under exactly that epoch or
    // publish nothing.
    let wrote_under_mutation_generation = state
        .replica_coordinator
        .dag_bump_mutation_fence(group_id, path, "restore_write")
        .map_err(|e| SyncError::CorruptState(format!("{path}: mutation fence bump failed: {e}")))?;
    // Set by the regular-file arm below when its replicated xattrs could
    // not be confirmed; the commit then publishes no exact proof.
    let mut xattrs_unproven = false;
    // A restored version carries its own `record_kind`/`unix_mode`/
    // `symlink_target` (captured per-row, not just for the `current` row
    // -- see `VersionRecord::record_kind`'s own doc comment); calling
    // `reconstruct_file` unconditionally regardless of kind would restore
    // a symlink or executable version as an ordinary, non-executable
    // regular file instead. Dispatch on the version's own
    // kind, matching `peer_session::materialize`'s and
    // `materialize_symlink_at`'s established per-kind materialization.
    match version.record_kind {
        yadorilink_replica_domain::file::RecordKind::File => {
            // A real writer of the volume like any other: it claims its space
            // in the shared account until the restore is done.
            let _headroom = if state.disk_headroom_enforcement_enabled() {
                let headroom_override =
                    state.governance_config.load_or_default().headroom_override_bytes;
                Some(preflight_disk_pressure(state, path, &root, version.size, headroom_override)?)
            } else {
                None
            };
            // Same whole-file assemble-and-write as `hydrate_inner`'s own
            // `reconstruct_file` above, reached from an async task the same
            // way — offloaded identically.
            // Assembled into a temp file first and published by rename only
            // after the local-edit guards are asked again: the assembly takes
            // time proportional to the file, and a save landing in it would
            // otherwise be renamed over, with nothing left to capture.
            let temp_ledger = state.replica_coordinator.temp_ledger(group_id);
            let tmp_path = run_blocking_sweep_offloaded(|| {
                yadorilink_local_storage::reconstruct_file_to_temp_in(
                    &crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                        state.block_store.clone(),
                    ),
                    &out_path,
                    &version.blocks,
                    // Not `version.mtime_unix_nanos` (that historical
                    // version's own original authored time) — a restore is
                    // authored by THIS device right now, same as
                    // `new_record.mtime_unix_nanos` above, which is what gets
                    // indexed for it. Stamping disk to match keeps the same
                    // on-disk/indexed-mtime invariant `reconstruct_file`'s own
                    // doc comment describes.
                    now_unix_nanos,
                    &temp_ledger,
                )
            })?;
            #[cfg(test)]
            run_restore_before_persist_hook(&out_path);
            let declined = restore_would_destroy_local_state(
                state,
                group_id,
                path,
                &out_path,
                initial_disk_identity,
                &version,
                &root_commit_permit,
            );
            if !matches!(declined, Ok(false)) {
                yadorilink_local_storage::discard_temp_file(&tmp_path, &temp_ledger);
                // The journal row stays: startup reconciliation reads the
                // disk and discards it, since the disk holds the local edit.
                declined?;
                return Err(SyncError::PathChangedLocally(format!("{group_id}/{path}")));
            }
            verify_root_before_publish(state, group_id, &root, &tmp_path, &temp_ledger)?;
            run_blocking_sweep_offloaded(|| {
                yadorilink_local_storage::persist_reconstructed_file_in(
                    &tmp_path,
                    &out_path,
                    &temp_ledger,
                )
            })?;
            // Confirmed inside this write, before the final mode. A restore
            // whose attributes cannot be confirmed still happened -- it is
            // not failed -- but it publishes no exact proof for them.
            let applied = yadorilink_local_storage::apply_file_metadata_verified(
                &out_path,
                version.unix_mode,
                &version.xattrs,
            )?;
            if let Err(refused) = yadorilink_local_storage::XattrEvidence::from(applied)
                .prove(&out_path, &version.xattrs)
            {
                tracing::warn!(
                    %path,
                    ?refused,
                    "could not confirm the replicated extended attributes this restore set; \
                     committing it without an exact proof"
                );
                xattrs_unproven = true;
            }
        }
        yadorilink_replica_domain::file::RecordKind::Symlink => match &version.symlink_target {
            Some(target) => materialize_restored_symlink(state, group_id, &out_path, target)?,
            None => {
                // No target recorded for this version -- nothing safe to
                // create on disk, matching `materialize_symlink_at`'s own
                // defensive handling of the same case. Unreachable in
                // practice, not just unlikely: `record_restore_operation_
                // emitting_change` above (line ~2043) validates this exact
                // `version.symlink_target` via `FileVersion::verify_hash`
                // before this dispatch ever runs, and that validation
                // rejects a targetless symlink outright -- so whenever this
                // arm would fire, the restore already failed earlier and
                // never reaches here. See `commit_restore_operation`'s own
                // doc comment for the full argument. Kept as explicit
                // defensive handling (not `unreachable!()`) rather than
                // leaning on that ordering never changing.
            }
        },
        yadorilink_replica_domain::file::RecordKind::Directory => {
            // The restored directory is the replicated entry itself; only
            // the ancestors it needs are structural, and they already exist:
            // the target verification above created them.
            let canonical_root = std::fs::canonicalize(&root)?;
            yadorilink_local_storage::create_explicit_directory(
                &out_path,
                &canonical_root,
                &yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger::new(
                    state.replica_coordinator.as_ref(),
                    group_id,
                ),
            )?;
            yadorilink_local_storage::apply_unix_mode(&out_path, version.unix_mode)?;
        }
    }
    // Marks the journal entry disk-committed, observes what the write
    // above left on disk (so the proof describes what a reader would now
    // find; `None` for the one arm that writes nothing), and commits.
    match state.replica_coordinator.settle_restore_write(
        &operation_id,
        &out_path,
        wrote_under_mutation_generation,
        !xattrs_unproven,
        &root_commit_permit,
    )? {
        yadorilink_replica_domain::session_state::RestoreCommitOutcome::Committed(_) => {}
        yadorilink_replica_domain::session_state::RestoreCommitOutcome::Missing => {
            return Err(SyncError::CorruptState(format!(
                "restore operation disappeared before index commit: {operation_id}"
            )));
        }
        yadorilink_replica_domain::session_state::RestoreCommitOutcome::Superseded => {
            return Err(SyncError::CorruptState(format!(
                "restore base changed before index commit: {group_id}/{path}"
            )));
        }
        // Something else mutated this path between this restore's own
        // write and its commit, so these bytes are no longer known to be
        // what is on disk. Nothing was published and the journal row
        // stands: startup recovery re-verifies the bytes and decides.
        yadorilink_replica_domain::session_state::RestoreCommitOutcome::FenceLost => {
            return Err(SyncError::CorruptState(format!(
                "another writer touched {group_id}/{path} during its restore; \
                 nothing was published and the restore journal entry remains"
            )));
        }
    };
    // Same follow-up as `DaemonState::on_local_native_commit`'s other callers
    // (`announce_local_change`): connected peers see this exactly like any
    // other local edit (spec "Restored content propagates like a normal
    // edit").
    // The last commit is done; release the operation before the fan-out,
    // which touches no root state.
    drop(root_op);
    state.on_local_native_commit(group_id).await;
    Ok(placement)
}

/// Whether replacing what is at `out_path` with a restored `version` would
/// destroy local state capture has not recorded: a regular file that is not
/// the current row's bytes (or any file at a path with no live row), a
/// change of the file since `baseline` was taken before the fetch, or a path
/// capture is still owed. A refusal journals the path for capture, so the
/// edit is taken as a change of its own instead of being found equal to
/// nothing later.
fn restore_would_destroy_local_state(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    out_path: &std::path::Path,
    baseline: DiskIdentity,
    version: &yadorilink_replica_domain::session_state::VersionRecord,
    permit: &yadorilink_root_authority::root_commit::RootCommitPermit<'_>,
) -> Result<bool, SyncError> {
    if journal_local_edit_seen_by_hydration(state, group_id, path, out_path, baseline, permit)?
        || state.replica_coordinator.dirty_path_repository().is_path_dirty(group_id, path)?
    {
        return Ok(true);
    }
    let destroys = match std::fs::symlink_metadata(out_path) {
        Ok(meta) if meta.is_dir() => false,
        Ok(meta) => {
            let tracked = state
                .replica_coordinator
                .file_index_repository()
                .canonical_current_row(group_id, path)?
                .is_some_and(|row| !row.snapshot.deleted);
            if tracked {
                state
                    .local_convergence()
                    .removal_would_destroy_unrecorded_state(group_id, path, out_path)
                    .map_err(|error| SyncError::CorruptState(error.to_string()))?
            } else {
                // Something this device has no live row for: a new local
                // file, unless it already holds exactly what is restored.
                !(meta.is_file()
                    && version.record_kind == yadorilink_replica_domain::file::RecordKind::File
                    && yadorilink_local_storage::disk_content_comparison(
                        out_path,
                        &version.blocks,
                    )? != yadorilink_local_storage::DiskContentComparison::PresentButDifferent)
            }
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            false
        }
        Err(error) => return Err(error.into()),
    };
    if destroys {
        state.replica_coordinator.journal_uncaptured_local_edit(group_id, path, true, permit)?;
    }
    Ok(destroys)
}

/// Test-only, one-shot, keyed by path: runs between a restore's assembly and
/// its final local-edit check.
#[cfg(test)]
type RestoreHooks = Vec<(String, Box<dyn FnOnce(&std::path::Path) + Send>)>;

#[cfg(test)]
pub(crate) static RESTORE_BEFORE_PERSIST_HOOK: std::sync::Mutex<RestoreHooks> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn run_restore_before_persist_hook(out_path: &std::path::Path) {
    let hook = {
        let mut hooks = RESTORE_BEFORE_PERSIST_HOOK.lock().unwrap_or_else(|p| p.into_inner());
        hooks
            .iter()
            .position(|(key, _)| *key == out_path.display().to_string())
            .map(|i| hooks.remove(i).1)
    };
    if let Some(hook) = hook {
        hook(out_path);
    }
}

/// The disk's half of whether a restore of a `kind` entry at `path` can
/// be written at `path` itself: no ancestor is a synced file or symlink
/// the namespace has to move aside first, and the path is not held by an
/// object of the other shape -- a directory where a file or symlink is
/// restored, or a file or symlink where a directory is. The namespace's
/// half (does it keep the entry at its own path at all) is asked by the
/// transaction that authors the restore.
fn restore_disk_allows_in_place(
    state: &DaemonState,
    group_id: &str,
    path: &str,
    root: &std::path::Path,
    kind: yadorilink_replica_domain::file::RecordKind,
) -> Result<bool, SyncError> {
    use yadorilink_replica_domain::file::RecordKind;
    // An ancestor that is a synced file or symlink is the namespace's to
    // move aside. Anything else in an ancestor's place (a local symlink
    // out of the root, say) is left to the write-target check, which
    // refuses it.
    let mut ancestor = std::path::Path::new(path).parent();
    while let Some(rel) = ancestor.filter(|rel| !rel.as_os_str().is_empty()) {
        let is_synced_leaf = || -> Result<bool, SyncError> {
            let rel = rel.to_string_lossy();
            Ok(state
                .replica_coordinator
                .file_index_repository()
                .get_file(group_id, &rel)?
                .is_some_and(|row| !row.deleted))
        };
        match std::fs::symlink_metadata(root.join(rel)) {
            Ok(metadata) if !metadata.is_dir() && is_synced_leaf()? => return Ok(false),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => return Err(error.into()),
        }
        ancestor = rel.parent();
    }
    match std::fs::symlink_metadata(root.join(path)) {
        Ok(metadata) => Ok(metadata.is_dir() == (kind == RecordKind::Directory)),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(true)
        }
        Err(error) => Err(error.into()),
    }
}

/// restores a trashed file — the last version before its
/// deletion (`SyncState::list_trashed`'s own `version_seq`, always the
/// *most recent* trashed row for `path` — see that method's doc comment)
/// — as a new current version via `restore_to_version` above. The file
/// becomes live again; the trashed row itself is left exactly as it was
/// (: restore never mutates existing version rows) — it simply
/// stops being "the last version before the current tombstone" once a
/// newer current version supersedes the tombstone.
pub async fn restore_trashed(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
) -> Result<(), SyncError> {
    let trashed = state.replica_coordinator.file_index_repository().list_trashed(group_id)?;
    let entry = trashed
        .into_iter()
        .find(|t| t.path == path)
        .ok_or_else(|| SyncError::NotFound(format!("no trashed file at {group_id}/{path}")))?;
    restore_to_version(state, group_id, path, entry.version_seq).await
}

pub use crate::application::ports::version_restore::TrashOperationRestore;

/// The folder restore: every trashed entry removed by the same recursive
/// delete or directory rename that removed the trashed entry at `path`,
/// each restored as [`restore_trashed`] restores one entry (so each is
/// placed by the namespace as it stands now), in path order -- a
/// directory before what was inside it.
///
/// The set is read from the trashed versions, which carry the operation
/// that removed them, so it does not depend on the removing changes still
/// being held. It is the set this device knows of: when a part of the
/// operation has not arrived, what that part removed is not here to
/// restore, and the outcome says the restore is partial. An entry that
/// fails to restore does not stop the others; each failure is reported.
pub async fn restore_trashed_operation(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
) -> Result<TrashOperationRestore, SyncError> {
    let index = state.replica_coordinator.file_index_repository();
    let entry = index
        .list_trashed(group_id)?
        .into_iter()
        .find(|t| t.path == path)
        .ok_or_else(|| SyncError::NotFound(format!("no trashed entry at {group_id}/{path}")))?;
    let operation = entry.deleted_by_operation.ok_or_else(|| {
        SyncError::NotFound(format!(
            "{group_id}/{path} was deleted on its own, not by a folder delete or rename"
        ))
    })?;
    let partial = !matches!(
        state.replica_coordinator.database().read::<_, yadorilink_sync_sqlite::SyncSqliteError>(
            |conn| yadorilink_sync_sqlite::native_recursive_operation::completeness(
                conn, group_id, &operation
            )
        )?,
        yadorilink_sync_sqlite::native_recursive_operation::NativeOperationCompleteness::Complete
    );
    let mut outcome = TrashOperationRestore { partial, ..TrashOperationRestore::default() };
    for trashed in index.list_trashed_by_recursive_operation(group_id, &operation)? {
        match restore_to_version(state, group_id, &trashed.path, trashed.version_seq).await {
            Ok(()) => outcome.restored.push(trashed.path),
            Err(error) => outcome.failed.push((trashed.path, error.to_string())),
        }
    }
    Ok(outcome)
}

/// spec "Restore without a version defaults to the most recent superseded
/// version": the `--version`-omitted default for `yadorilink restore
/// <path>`. `None` if the path has no superseded version to
/// restore to (only ever a `current` row, or no row at all).
pub fn most_recent_superseded_version_seq(
    state: &DaemonState,
    group_id: &str,
    path: &str,
) -> Result<Option<i64>, SyncError> {
    Ok(state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(group_id, path)?
        .into_iter()
        .find(|v| v.state == yadorilink_replica_domain::session_state::VersionState::Superseded)
        .map(|v| v.version_seq))
}

/// Currently-connected, authorized-for-`group_id` sessions, paired with
/// their peer device id (the `BlockWorkQueue`'s "tried-by" key) — the
/// `state.peers.sessions` map is already keyed by device id, so this just
/// filters and preserves that pairing instead of discarding it.
pub(crate) fn candidate_sessions(
    state: &DaemonState,
    group_id: &str,
) -> Vec<(String, Arc<PeerSyncSession>)> {
    state.peers.sessions_for_group(group_id)
}

/// Resolves every block `blocks` references to a locally-present,
/// checksum-valid copy, fetching only genuinely-needed blocks from
/// currently-reachable peers. Shared by `hydrate_inner` and
/// `restore_to_version_inner` so the resolution *ordering* lives in exactly
/// one place instead of being duplicated (and previously diverging) between
/// the two.
///
/// Local-present-first: a block already cached locally is never fetched, so
/// content whose blocks are all present (and intact) resolves without
/// contacting any peer at all and therefore succeeds while offline. A peer
/// is consulted only for blocks that are missing — or that exist locally
/// but fail their checksum (corruption): those are treated as missing so a
/// peer holding a good copy repairs them (the fetch path's `put` overwrites
/// the corrupt bytes). The corruption check runs only when a peer is
/// actually reachable to fix it; with no candidate peer a corrupt-but-
/// present block is left in place for the ordinary corrupt-repair path
/// rather than forcing a pointless fetch attempt.
///
/// Returns the blocks still unavailable after any fetch — empty means every
/// block is now present locally. The caller maps a non-empty result to its
/// own operation-specific error (`HydrationFailed` vs
/// `VersionContentUnavailable`).
async fn resolve_blocks_local_first(
    state: &DaemonState,
    group_id: &str,
    path: &str,
    blocks: &[BlockInfo],
    stall: Option<&Arc<HydrationStallTracker>>,
) -> Result<Vec<BlockInfo>, SyncError> {
    let hashes: Vec<String> = blocks.iter().map(|b| hex::encode(&b.hash)).collect();
    let present = state.block_store.present_blocks(&hashes)?;
    let candidates = candidate_sessions(state, group_id);

    let mut missing = Vec::new();
    for ((block, hash), already_present) in blocks.iter().zip(hashes.iter()).zip(present) {
        let has_group_provenance = state
            .replica_coordinator
            .sqlite()
            .dag_group_has_block_provenance(group_id, &block.hash)?;
        if !already_present || !has_group_provenance {
            missing.push(block.clone());
            continue;
        }
        // Present locally: only re-fetch if it's actually corrupt AND a
        // peer is reachable to supply a good copy. `get` verifies the
        // stored bytes against their hash; a `ChecksumMismatch` means the
        // on-disk block is corrupt, so it must be treated as missing
        // rather than counted as already-satisfied.
        if !candidates.is_empty()
            && matches!(
                {
                    let _reads = yadorilink_local_storage::io_diag::attribute_reads(
                        yadorilink_local_storage::io_diag::ReadReason::Validate,
                    );
                    state.block_store.get(hash)
                },
                Err(StorageError::ChecksumMismatch { .. })
            )
        {
            missing.push(block.clone());
        }
    }

    if missing.is_empty() {
        return Ok(Vec::new());
    }

    // Registers this file as an active transfer for the *missing* blocks
    // only (already-present blocks never touch the network, so they're not
    // part of "progress" toward completing this fetch) — torn down
    // automatically (whatever the outcome) once `_progress_guard` drops.
    let bytes_total: u64 = missing.iter().map(|b| b.size as u64).sum();
    if let Some(fetched) = stall.and_then(|stall| stall.fetched.as_ref()) {
        fetched.plan_fetch(bytes_total);
    }
    let blocks_total = missing.len() as u64;
    let _progress_guard = state.telemetry.begin_transfer(group_id, path, bytes_total, blocks_total);

    // Now that the actual missing blocks (and their real sizes) are known,
    // raise the stall budget to cover this dispatch's own worst case --
    // see `HydrationStallTracker`'s own doc comment for why a caller-
    // supplied flat deadline alone isn't enough once a single block's own
    // response deadline can itself approach or exceed it.
    if let Some(stall) = stall {
        if let Some(&max_missing_size) = missing.iter().map(|b| b.size as u64).max().as_ref() {
            stall.raise_budget(
                PeerSyncSession::fetch_response_timeout_for(max_missing_size) * 2
                    + STALL_BUDGET_MARGIN,
            );
        }
    }

    // Provenance for each block is recorded inside `fetch_blocks_from_
    // sessions` itself, immediately after that block's bytes are durably
    // persisted -- not batched here after the whole dispatch returns. See
    // that function's own doc comment on the success arm for why: this
    // call is itself wrapped in an outer stall deadline (`hydrate_with_
    // timeout`'s `run_with_stall_deadline`), and a stall firing mid-
    // dispatch drops this future before any code here would run, silently
    // losing provenance for blocks that were genuinely, durably fetched
    // moments before.
    let unresolved = fetch_blocks_from_sessions(
        group_id,
        path,
        missing,
        &candidates,
        state.block_store.clone(),
        state.replica_coordinator.clone(),
        state.telemetry.transfer_progress_handle(),
        state.telemetry.recent_errors_handle(),
        stall.cloned(),
        LaneStop::new(),
    )
    .await?;
    Ok(unresolved.remaining)
}

/// Fetches the blocks of a version that no index row names (a recovery item's) from the
/// connected peers: the blocks still unavailable afterwards, empty when every block is held.
pub(crate) async fn fetch_unindexed_blocks(
    state: &DaemonState,
    group_id: &str,
    blocks: &[BlockInfo],
) -> Result<Vec<BlockInfo>, SyncError> {
    resolve_blocks_local_first(state, group_id, "preserved version", blocks, None).await
}

pub(crate) fn local_root_for_group(
    state: &DaemonState,
    group_id: &str,
) -> Result<std::path::PathBuf, SyncError> {
    // Delegates rather than scanning `list_links` itself: an unordered `.find()`
    // silently took the FIRST match when a group had two live links, which is a
    // guess about which folder the user's files belong in. An orphaned link's
    // coordination-side authorization is gone -- treated the same as "no link
    // registered" here (the primitive filters `orphaned` for us), so hydration
    // never fetches/writes on-demand content into a folder that is no longer a
    // live sync target.
    state
        .replica_coordinator
        .link_repository()
        .live_link_local_path_for_group(group_id)?
        .map(std::path::PathBuf::from)
        .ok_or_else(|| SyncError::NotFound(format!("no link registered for group {group_id}")))
}

fn block_data_matches(block: &BlockInfo, data: &[u8]) -> bool {
    if data.len() != block.size as usize {
        return false;
    }
    let digest = Sha256::digest(data);
    digest[..] == block.hash[..]
}

pub(crate) mod directory;
pub(crate) mod rewind_prefetch;

#[cfg(test)]
mod tests;
