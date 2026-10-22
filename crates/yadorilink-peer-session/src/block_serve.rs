//! Source-side shared block serving: fair
//! in-flight-byte credit across peers/groups/the whole device, and
//! disk-read/hash-verify/compression coalescing so concurrent requesters for
//! the identical block share one read instead of each paying for their own.
//!
//! Lives in this crate, not `yadorilink-daemon`, even though it is logically
//! "one instance per daemon, not per session" (mirroring `DaemonState`'s
//! `block_store: Arc<dyn BlockStore>`): `PeerSyncSession::handle_block_request`
//! (this crate) is where serving actually happens, and this crate cannot
//! depend on `yadorilink-daemon` (wrong layering direction). `DaemonState`
//! constructs one [`BlockServeEngine`] and hands every session an `Arc` to
//! it via `PeerSyncSession::set_block_serve_engine`, exactly like it already
//! shares one `block_store` — see that method's own doc comment for why this
//! is a post-construction setter rather than a new required constructor
//! parameter (avoiding a blast-radius change across ~60 existing
//! `PeerSyncSession::new` call sites, nearly all of
//! them tests that have no reason to care about serve credit).
//!
//! There is no negotiated fallback for a session with no engine installed:
//! block serving is mandatory for every peer that reaches a session. A
//! session that reaches `handle_block_request` with no engine set (a
//! programming error in this codebase's own construction; see
//! `set_block_serve_engine`'s own doc comment) fails closed with
//! `Rejected` rather than falling back to some other response shape.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex, Weak};

use bytes::Bytes;
use tokio::sync::OnceCell;

/// The result of `BlockServeCredit::try_admit` when service is not
/// immediately possible under this engine's bounds. Carries the same two
/// fields `BlockBusy` puts on the wire, so the caller can build that
/// response directly rather than translating.
/// Held for the lifetime of one `BlockRequest`'s examination and service —
/// see `BlockServeEngine::try_begin_examination`'s own doc. Opaque: the only
/// operation is dropping it, which releases the slot back to the device-wide
/// examination budget — the field is intentionally write-only from this
/// crate's perspective, so its value is never read, only held.
#[derive(Debug)]
pub struct ExaminationPermit(#[allow(dead_code)] tokio::sync::OwnedSemaphorePermit);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeBusy {
    pub retry_after_ms: u32,
    /// How many requests are currently in flight for whichever budget
    /// (peer/group/global) was the tightest constraint -- an approximation
    /// of "how backed up is the thing you're contending on", not a real
    /// FIFO position (this engine does not queue or reorder requests; it
    /// only ever admits-or-denies, so contention resolves via each denied
    /// requester's own retry, not by this engine tracking their order).
    pub queue_depth: u32,
}

/// Per-scope (peer, group, or the whole device) in-flight accounting: how
/// many bytes and how many distinct requests are currently admitted.
#[derive(Default)]
struct ScopeUsage {
    bytes: u64,
    requests: u32,
}

/// Enforces per-peer, per-group, and global in-flight-byte budgets,
/// simultaneously -- none alone sufficient) by admission control: a request
/// is either admitted in full against all three budgets at once, or denied
/// with [`ServeBusy`]. There is no queueing or reordering here -- "fair
/// queue... by bytes, not request count" is achieved by the
/// budgets themselves being byte-denominated (a peer already using a large
/// share of the global budget is denied further admission regardless of how
/// few requests it has sent, and a peer sending many small requests cannot
/// starve one sending fewer, larger ones the way a request-count limit
/// would), not by a scheduler picking whose turn is next.
/// All in-flight accounting behind ONE lock: `try_admit` must check all
/// three budgets and, if every one passes, commit to all three before
/// releasing it -- checking and committing under separate locks (or
/// separate atomics) lets two concurrent requests both observe pre-commit
/// usage and both be admitted, overshooting every budget by up to the
/// second request's size (confirmed: this is exactly what the previous
/// per-field-locked version allowed).
#[derive(Default)]
struct BlockServeCreditState {
    global_bytes: u64,
    per_peer: HashMap<String, ScopeUsage>,
    per_group: HashMap<String, ScopeUsage>,
}

struct BlockServeCredit {
    max_global_bytes: u64,
    max_per_peer_bytes: u64,
    max_per_group_bytes: u64,
    state: StdMutex<BlockServeCreditState>,
}

/// Default fixed retry hint handed back in a `ServeBusy` -- this engine
/// tracks no ETA for when a specific in-flight request will actually
/// complete (that depends on this device's own disk/network conditions), so
/// it advertises a small, jittered, bounded wait rather than a computed
/// prediction; the requester's own bounded retry loop
/// (`PeerSyncSession::BUSY_RETRY_ATTEMPTS`) re-asks rather than trusting
/// this as an exact schedule.
const DEFAULT_RETRY_AFTER_MS: u32 = 150;

impl BlockServeCredit {
    fn new(max_global_bytes: u64, max_per_peer_bytes: u64, max_per_group_bytes: u64) -> Self {
        Self {
            max_global_bytes,
            max_per_peer_bytes,
            max_per_group_bytes,
            state: StdMutex::new(BlockServeCreditState::default()),
        }
    }

    /// Attempts to admit `bytes` of serving for `(peer_id, group_id)`, under
    /// one lock held across both the check and the commit -- a request that
    /// would fit the global and per-group budgets but not the per-peer one
    /// is denied outright, not partially admitted, and no concurrent caller
    /// can observe the pre-commit usage this call is about to invalidate.
    fn try_admit(&self, peer_id: &str, group_id: &str, bytes: u64) -> Result<(), ServeBusy> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.global_bytes.saturating_add(bytes) > self.max_global_bytes {
            return Err(ServeBusy {
                retry_after_ms: DEFAULT_RETRY_AFTER_MS,
                queue_depth: state.per_peer.values().map(|u| u.requests).sum(),
            });
        }
        let peer_usage = state.per_peer.get(peer_id).map(|u| u.bytes).unwrap_or(0);
        if peer_usage.saturating_add(bytes) > self.max_per_peer_bytes {
            return Err(ServeBusy {
                retry_after_ms: DEFAULT_RETRY_AFTER_MS,
                queue_depth: state.per_peer.get(peer_id).map(|u| u.requests).unwrap_or(0),
            });
        }
        let group_usage = state.per_group.get(group_id).map(|u| u.bytes).unwrap_or(0);
        if group_usage.saturating_add(bytes) > self.max_per_group_bytes {
            return Err(ServeBusy {
                retry_after_ms: DEFAULT_RETRY_AFTER_MS,
                queue_depth: state.per_group.get(group_id).map(|u| u.requests).unwrap_or(0),
            });
        }

        state.global_bytes += bytes;
        let peer = state.per_peer.entry(peer_id.to_string()).or_default();
        peer.bytes += bytes;
        peer.requests += 1;
        let group = state.per_group.entry(group_id.to_string()).or_default();
        group.bytes += bytes;
        group.requests += 1;
        Ok(())
    }

    fn release(&self, peer_id: &str, group_id: &str, bytes: u64) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.global_bytes = state.global_bytes.saturating_sub(bytes);
        if let Some(usage) = state.per_peer.get_mut(peer_id) {
            usage.bytes = usage.bytes.saturating_sub(bytes);
            usage.requests = usage.requests.saturating_sub(1);
            if usage.bytes == 0 && usage.requests == 0 {
                state.per_peer.remove(peer_id);
            }
        }
        if let Some(usage) = state.per_group.get_mut(group_id) {
            usage.bytes = usage.bytes.saturating_sub(bytes);
            usage.requests = usage.requests.saturating_sub(1);
            if usage.bytes == 0 && usage.requests == 0 {
                state.per_group.remove(group_id);
            }
        }
    }
}

/// Releases its slice of all three budgets when dropped -- including on an
/// early return/panic while a request is in flight, so a failed serve
/// attempt can never leak credit that a future request would then be wrongly
/// denied against.
pub struct ServeCreditGuard {
    engine: Arc<BlockServeEngine>,
    peer_id: String,
    group_id: String,
    bytes: u64,
}

impl std::fmt::Debug for ServeCreditGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeCreditGuard")
            .field("peer_id", &self.peer_id)
            .field("group_id", &self.group_id)
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Drop for ServeCreditGuard {
    fn drop(&mut self) {
        self.engine.credit.release(&self.peer_id, &self.group_id, self.bytes);
    }
}

/// A byte-fair ("fair queue... by bytes, not request count")
/// admission gate keyed by `(peer_id, group_id)`: bounds how many requests
/// are actively being served AT ONCE to a number deliberately much smaller
/// than `BlockServeCredit`'s byte budgets alone would allow, so real
/// queueing actually happens under load -- `BlockServeCredit` alone cannot
/// provide cross-peer/cross-group fairness, because if the byte budgets are
/// large relative to typical block sizes (the common case), every request
/// gets admitted and dispatched immediately with no queue for a fairness
/// policy to act on at all. This is what makes the per-peer/per-group
/// budgets' fairness ACTUALLY bite: a large backlog from one (peer, group)
/// occupies at most `max_active` concurrent slots, and every further
/// request from that SAME key waits its turn against every OTHER key with
/// an outstanding waiter, so a late request from a different peer or group
/// is never stuck behind an already-established large backlog for long.
///
/// Picks the next waiting key by LEAST CUMULATIVE BYTES GRANTED so far
/// (`bytes_granted`), not plain per-key round robin: a key that has been
/// granted many small requests and one that has been granted few large
/// ones can reach the identical BYTE total from very different request
/// COUNTS, and a scheduler that instead rotated strictly by turn count
/// would let the key sending many 1 KiB requests dominate one sending a
/// few 16 MiB requests just as easily as the reverse -- neither matches
/// "fair... by bytes, not request count." `bytes_granted` is rebased down
/// by its own current minimum on every grant (see `release_and_wake_next`)
/// so it stays bounded across a long-running connection instead of
/// growing forever; only the RELATIVE ordering between keys ever matters
/// for which is picked next, and shifting every entry down by the same
/// amount preserves that ordering exactly.
/// `(cost_bytes, reply sender)` for one queued dispatch waiter.
/// One queued dispatch waiter. `id` lets a cancelled `acquire` call find and
/// remove exactly this entry (never a different waiter for the same key) --
/// see `WaiterCancelGuard`'s own doc comment.
struct DispatchWaiter {
    id: u64,
    cost: u64,
    tx: tokio::sync::oneshot::Sender<FairDispatchGuard>,
}

struct FairDispatchState {
    waiters: HashMap<(String, String), VecDeque<DispatchWaiter>>,
    /// Cumulative bytes granted to each key so far (see this struct's own
    /// doc comment). Only keys that have been granted at least once have
    /// an entry; a key with no entry is treated as `0`. Only ever
    /// incremented after a waiter's guard has actually been handed off
    /// (`tx.send` succeeded) -- a cancelled/timed-out waiter that never
    /// received a guard must never be charged bytes it was never served
    /// (see `release_and_wake_next`'s own doc comment).
    bytes_granted: HashMap<(String, String), u64>,
    active: usize,
    /// Sum of every `waiters` queue's length, maintained incrementally so
    /// `acquire` can enforce `max_waiting` without an O(keys) scan on every
    /// call. Decremented immediately on cancellation (`WaiterCancelGuard`),
    /// not only when `release_and_wake_next` eventually reaches a stale
    /// entry in rotation -- otherwise `max_waiting`'s capacity would stay
    /// artificially exhausted by dead entries for as long as it takes
    /// rotation to reach them, rejecting new requests that would otherwise
    /// fit.
    waiting: usize,
    /// Monotonic id assigned to each queued waiter, so `WaiterCancelGuard`
    /// can find and remove exactly the one entry it owns.
    next_waiter_id: u64,
}

struct FairDispatchQueue {
    state: StdMutex<FairDispatchState>,
    max_active: usize,
    /// Hard cap on how many requests may be queued (not yet actively being
    /// served) at once, device-wide, regardless of key -- an authorized
    /// peer that simply floods requests faster than they can be served
    /// would otherwise grow `waiters` (and the spawned task + oneshot
    /// channel behind each entry) without bound. Once this many are
    /// already queued, `acquire` rejects a new one outright (`Err`,
    /// answered `Busy`) instead of adding a waiter that might sit for a
    /// very long time regardless.
    max_waiting: usize,
}

impl FairDispatchQueue {
    fn new(max_active: usize, max_waiting: usize) -> Self {
        Self {
            state: StdMutex::new(FairDispatchState {
                waiters: HashMap::new(),
                bytes_granted: HashMap::new(),
                active: 0,
                waiting: 0,
                next_waiter_id: 0,
            }),
            max_active,
            max_waiting,
        }
    }

    /// Waits for a fair turn to serve `(peer_id, group_id)`'s `cost_bytes`-
    /// sized request. Returns immediately if fewer than `max_active`
    /// requests are currently being served; otherwise queues behind this
    /// key's own prior waiters (FIFO within a key) and waits its turn,
    /// picked by least cumulative bytes granted so far against every other
    /// key with an outstanding waiter (see `FairDispatchState`'s own doc
    /// comment) -- unless `max_waiting` requests are already queued
    /// device-wide, in which case this returns `Err` immediately rather
    /// than adding another (see `max_waiting`'s own doc comment).
    ///
    /// The granted slot is a [`FairDispatchGuard`] from the moment it is
    /// granted (either here, on the fast path, or inside
    /// `release_and_wake_next`, on the slow path) -- never a bare `()`
    /// signal that this function turns into a guard only after resuming.
    /// That makes the wait itself cancel-safe: if this future (or its
    /// enclosing task) is dropped at ANY point after a slot is granted --
    /// including after `release_and_wake_next` has already sent the guard
    /// but before this function is ever polled again to receive it -- the
    /// oneshot channel drops the buffered guard along with the `Receiver`,
    /// which runs `FairDispatchGuard::drop` and releases the slot exactly
    /// as if this call had completed normally. A design that instead sent
    /// `()` and constructed the guard only after `rx.await` resolved would
    /// leak the slot in that same window: `active` would already be
    /// incremented with nothing left alive to decrement it. This also
    /// means a caller that wraps this call in `tokio::time::timeout` to
    /// bound the wait (not just the queue depth) can safely let it elapse
    /// at any point -- dropping the timed-out future never leaks a slot.
    ///
    /// While still QUEUED (not yet granted), cancellation is ALSO handled
    /// promptly rather than left for `release_and_wake_next` to discover
    /// whenever rotation eventually reaches this entry: `WaiterCancelGuard`
    /// removes it from `waiters` and decrements `waiting` immediately when
    /// this future is dropped before being granted, so `max_waiting`'s
    /// capacity recovers as soon as a caller actually gives up, not only
    /// once an active request elsewhere happens to finish and rotation
    /// happens to reach the stale entry.
    async fn acquire(
        self: &Arc<Self>,
        peer_id: &str,
        group_id: &str,
        cost_bytes: u64,
    ) -> Result<FairDispatchGuard, ServeBusy> {
        let (key, id, rx) = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let key = (peer_id.to_string(), group_id.to_string());
            if state.active < self.max_active {
                state.active += 1;
                // Tracked even on this immediate-admit fast path -- a key
                // that got a free pass with a huge request must still show
                // up as having consumed bytes, or a later queueing
                // decision against it would be comparing against a
                // baseline that silently ignored its biggest requests.
                *state.bytes_granted.entry(key).or_insert(0) += cost_bytes.max(1);
                return Ok(FairDispatchGuard { queue: self.clone() });
            }
            if state.waiting >= self.max_waiting {
                return Err(ServeBusy {
                    retry_after_ms: DEFAULT_RETRY_AFTER_MS,
                    queue_depth: state.waiting as u32,
                });
            }
            let id = state.next_waiter_id;
            state.next_waiter_id += 1;
            let (tx, rx) = tokio::sync::oneshot::channel();
            state.waiters.entry(key.clone()).or_default().push_back(DispatchWaiter {
                id,
                cost: cost_bytes,
                tx,
            });
            state.waiting += 1;
            (key, id, rx)
        };
        // Armed for the entire wait; its `Drop` is a safe no-op once this
        // waiter has actually been granted (by then `release_and_wake_next`
        // has already popped it out of `waiters`, so there's nothing left
        // to find and remove) -- see `WaiterCancelGuard`'s own doc comment.
        let _cancel_guard = WaiterCancelGuard { queue: self, key, id };
        // Resolves to the already-constructed guard `release_and_wake_next`
        // sent once it granted this waiter its turn; see this function's
        // own doc comment for why an early drop of this `.await` is safe.
        Ok(rx.await.expect("oneshot sender never dropped without sending a guard"))
    }

    /// How many requests are currently queued (granted no slot yet). Test-
    /// only accessor.
    #[cfg(test)]
    fn waiting_count(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).waiting
    }

    #[allow(
        clippy::excessive_nesting,
        reason = "one release-and-rotate critical section held under a single non-reentrant \
                  StdMutex guard: the loop skips stale/empty waiter queues, the send match \
                  distinguishes a granted slot from a waiter cancelled mid-grant, and the \
                  bytes_granted rebase nests inside the granted arm. Extracting any inner \
                  level would either have to re-lock the mutex (self-deadlock) or pass the \
                  guard around, and the Err arm's mem::forget only stays sound while it is \
                  lexically inside the lock scope it reuses on the next iteration."
    )]
    fn release_and_wake_next(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.active -= 1;
        loop {
            let key = {
                let bytes_granted = &state.bytes_granted;
                state
                    .waiters
                    .keys()
                    .min_by_key(|k| bytes_granted.get(*k).copied().unwrap_or(0))
                    .cloned()
            };
            let Some(key) = key else { return };
            let Some(queue) = state.waiters.get_mut(&key) else { continue };
            let Some(waiter) = queue.pop_front() else { continue };
            let now_empty = queue.is_empty();
            state.waiting -= 1;
            if now_empty {
                state.waiters.remove(&key);
            }
            state.active += 1;
            let guard = FairDispatchGuard { queue: self.clone() };
            match waiter.tx.send(guard) {
                Ok(()) => {
                    // Only charged to `bytes_granted` NOW, after the guard
                    // has actually been handed off -- a waiter that never
                    // received one (the `Err` arm below) must never be
                    // charged bytes it was never served; see
                    // `FairDispatchState::bytes_granted`'s own doc comment
                    // for why crediting this unconditionally (the previous
                    // version of this function did, right after `state.
                    // active += 1` above) let a flood of cancelled large
                    // requests permanently starve that same key's later,
                    // legitimate ones.
                    *state.bytes_granted.entry(key).or_insert(0) += waiter.cost.max(1);
                    // Rebase every entry down by the current minimum so
                    // `bytes_granted` stays bounded across a long-running
                    // connection -- see `FairDispatchState`'s own doc
                    // comment for why this changes nothing about which key
                    // gets picked next.
                    if let Some(&min) = state.bytes_granted.values().min() {
                        if min > 0 {
                            for v in state.bytes_granted.values_mut() {
                                *v -= min;
                            }
                        }
                    }
                    return;
                }
                Err(guard) => {
                    // The waiter was dropped (its task was cancelled)
                    // before this grant reached it -- `send` handed the
                    // guard back rather than running its `Drop` itself.
                    // Suppress that `Drop` with `mem::forget`: letting it
                    // run would call `release_and_wake_next` again while
                    // THIS call still holds `state`'s lock (a plain
                    // `StdMutex`, not reentrant) and deadlock. The `active
                    // -= 1` right here is the only bookkeeping an
                    // un-granted slot needs (deliberately NOT touching
                    // `bytes_granted` -- see the `Ok` arm above), and this
                    // loop already does it under the lock it's about to
                    // reuse for the next candidate. In practice
                    // `WaiterCancelGuard` removes a cancelled waiter from
                    // `waiters` immediately, so this arm should be rare
                    // (only the narrow window where cancellation and this
                    // grant race for the same lock) rather than the common
                    // path it used to be.
                    std::mem::forget(guard);
                    state.active -= 1;
                }
            }
        }
    }
}

/// Removes waiter `id` from `queue`'s `waiters[key]` on drop, IF it's still
/// there -- armed for the entire time `FairDispatchQueue::acquire` is
/// waiting on its oneshot `Receiver`, so a cancelled/timed-out wait (e.g.
/// the caller's own `tokio::time::timeout` elapsing) recovers `waiting`'s
/// capacity immediately rather than leaving a dead entry for
/// `release_and_wake_next` to discover only once rotation happens to reach
/// it. A no-op once this waiter has actually been granted its turn --
/// `release_and_wake_next` already popped it out of `waiters` by then, so
/// there's nothing left with this `id` to find.
struct WaiterCancelGuard<'a> {
    queue: &'a Arc<FairDispatchQueue>,
    key: (String, String),
    id: u64,
}

impl Drop for WaiterCancelGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.queue.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(queue) = state.waiters.get_mut(&self.key) else { return };
        let Some(pos) = queue.iter().position(|w| w.id == self.id) else { return };
        queue.remove(pos);
        let now_empty = queue.is_empty();
        state.waiting -= 1;
        if now_empty {
            state.waiters.remove(&self.key);
        }
    }
}

pub struct FairDispatchGuard {
    queue: Arc<FairDispatchQueue>,
}

impl Drop for FairDispatchGuard {
    fn drop(&mut self) {
        self.queue.release_and_wake_next();
    }
}

/// A (cheaply cloneable) reason `CoalescedBlock`'s read/verify/compress
/// failed -- kept distinct from a plain `String` so the caller can tell a
/// `SizeMismatch` (the stored bytes don't match what the referencing
/// version declared -- a serve-boundary invariant check, not an ordinary
/// read failure) apart from `ReadFailed` (the store simply couldn't
/// produce the bytes) without parsing message text. A `SizeMismatch`
/// warrants a hard `Rejected` reply (this device's own state is
/// inconsistent, retrying won't fix it). `Absent` (the store does not hold
/// the bytes) is the one failure that truthfully answers `DontHave`;
/// `ReadFailed` (the bytes are there but could not be read back intact) is
/// answered `Rejected`, so a requester never mistakes a holder's local read
/// failure for the content not existing.
#[derive(Debug, Clone)]
pub enum CoalesceFailure {
    Absent(String),
    ReadFailed(String),
    SizeMismatch(String),
}

/// The coalesced result of one `(group_id, hash)` disk read: the verified
/// plaintext bytes and the wire compression it was encoded with, or a
/// [`CoalesceFailure`] if the read/verify/compress/size-check failed. Every
/// concurrent requester for the same key gets a reference-counted clone of
/// the SAME `Bytes`, not its own copy.
pub type CoalescedBlock = Result<(Bytes, i32), CoalesceFailure>;

type CoalesceCell = OnceCell<CoalescedBlock>;
/// Keyed by `(group_id, hash, expected_size)` -- see `coalesce_cell`'s own
/// doc comment for why the expected size must be part of the key, not just
/// an input the first caller's initializer closure happens to check.
type CoalesceMap = StdMutex<HashMap<(String, Vec<u8>, Option<u64>), Weak<CoalesceCell>>>;

/// Owns both the credit accounting and the read-coalescing map. One instance
/// is shared across every `PeerSyncSession` on a daemon (see this module's
/// doc comment) -- credit and coalescing both need a device-wide view to
/// mean anything; a per-session instance of either would defeat the point.
pub struct BlockServeEngine {
    credit: BlockServeCredit,
    coalesce: CoalesceMap,
    /// The actual cross-peer/cross-group fairness mechanism (see
    /// `FairDispatchQueue`'s own doc comment for why `BlockServeCredit`'s
    /// byte budgets alone cannot provide this: when the byte budgets are
    /// generous relative to typical block sizes -- the common, desired
    /// case -- every request gets admitted and dispatched at once, with no
    /// backlog for a fairness policy to act on). Its `max_active` is
    /// the `max_inflight_requests` this engine was built with, not an
    /// independent constant.
    dispatch: Arc<FairDispatchQueue>,
    /// Bounds how many `BlockRequest`s this device EXAMINES (authorization,
    /// reference and provenance checks, all before `acquire_dispatch_turn`
    /// ever runs) concurrently, device-wide. See `try_begin_examination`'s
    /// own doc for the gap this closes.
    examination_admission: Arc<tokio::sync::Semaphore>,
    /// The permit count `examination_admission` was constructed with --
    /// `tokio::sync::Semaphore` exposes only `available_permits`, not its
    /// original capacity, so this is kept alongside to derive a `queue_
    /// depth` for `ServeBusy` without a second bookkeeping structure.
    examination_admission_capacity: usize,
}

/// How many requests may be QUEUED (not yet actively dispatched) at once,
/// as a multiple of `max_inflight_requests` -- a generous cushion for
/// legitimate bursts while still bounding worst-case queued-waiter growth
/// (each entry is a spawned task's oneshot channel) against a peer that
/// simply floods requests faster than they can be served. Not tuned as
/// tightly as `max_inflight_requests` itself: this only needs to be "large
/// enough to rarely reject a burst that would drain in reasonable time,
/// small enough to bound memory", not tuned against a specific fairness
/// test's exact position assertion.
const MAX_WAITING_MULTIPLE: usize = 8;

impl BlockServeEngine {
    /// `max_inflight_requests` is the tuned value described below --
    /// changing it changes both what this device advertises AND the real
    /// concurrent-dispatch cap (`FairDispatchQueue`'s `max_active`), which
    /// used to be two independently-set, silently-diverging numbers (this
    /// device advertising 64 worker slots while the dispatch queue itself
    /// only ever actually ran 16 at once -- a peer favoring this device as
    /// a source based on that advertised figure was reading a number this
    /// device could never back up).
    ///
    /// The first `max_inflight_requests` requests overall are ALWAYS
    /// admitted immediately regardless of key (`FairDispatchQueue::acquire`'s
    /// own doc comment: fairness only governs who's picked NEXT once every
    /// slot is already taken) -- so this value trades off directly against
    /// `stage2_block_serve_contract.rs`'s own fairness test, which requires
    /// a late-arriving request to land within the first 32 entries overall.
    /// Measured 8 as too small (materially slowed real multi-device
    /// throughput: `taguchi_collision_matrix`'s full suite roughly doubled
    /// in wall time by needlessly serializing legitimate concurrent serving
    /// even under ordinary, uncontended load) and 32 as leaving no headroom
    /// at all (the initial free pass alone already consumes the entire
    /// budget the test allows, before round-robin fairness ever gets to
    /// act). 16 leaves the fairness mechanism 2-3 rounds of headroom under
    /// that bound while still doubling 8's concurrency -- this codebase's
    /// own `DaemonState` passes 16 for exactly this reason; a caller
    /// picking a different value should re-validate both that throughput
    /// measurement and the fairness test this was tuned against.
    pub fn new(
        max_global_bytes: u64,
        max_per_peer_bytes: u64,
        max_per_group_bytes: u64,
        max_inflight_requests: u32,
    ) -> Arc<Self> {
        let max_active = max_inflight_requests as usize;
        // Same size as the fairness queue's own waiting capacity: this
        // budget must never be the FIRST thing to reject a request the
        // fairness queue would itself have accepted — see `try_begin_
        // examination`'s own doc for what it exists to catch instead.
        let examination_capacity = max_active.saturating_mul(MAX_WAITING_MULTIPLE);
        Arc::new(Self {
            credit: BlockServeCredit::new(
                max_global_bytes,
                max_per_peer_bytes,
                max_per_group_bytes,
            ),
            coalesce: StdMutex::new(HashMap::new()),
            dispatch: Arc::new(FairDispatchQueue::new(
                max_active,
                max_active.saturating_mul(MAX_WAITING_MULTIPLE),
            )),
            examination_admission: Arc::new(tokio::sync::Semaphore::new(examination_capacity)),
            examination_admission_capacity: examination_capacity,
        })
    }

    /// Non-blocking pre-admission gate for a `BlockRequest`, to be called
    /// BEFORE spawning a handler task for it — never after.
    ///
    /// The real concurrency/fairness mechanism is `acquire_dispatch_turn`
    /// below, and this is deliberately not a second copy of it: it is a
    /// coarse, cheap admission-control budget for the EXAMINATION work
    /// (`shares_group`, the reference lookup, the provenance check, and the
    /// spawned task itself) that unavoidably happens BEFORE a request ever
    /// reaches `acquire_dispatch_turn`. Without this, an authorized peer
    /// that simply sends `BlockRequest`s faster than this device can
    /// examine them grows that unbounded work — spawned tasks, SQLite/native-state
    /// lookups, per-task future state — with no cap at all, even though
    /// `acquire_dispatch_turn`'s own queue-full rejection (`Err` at `max_
    /// active * MAX_WAITING_MULTIPLE` waiters) looks like a bound from the
    /// caller's side. `try_acquire_owned` is instant: it either succeeds
    /// with a permit or fails immediately, so unlike a real queue it can
    /// never make an admitted request wait behind another, and so cannot
    /// reintroduce the per-session head-of-line-blocking problem this
    /// module's own history already ruled out a queue for (see this
    /// module's other doc comments on that).
    ///
    /// Hold the returned permit for exactly as long as the request is being
    /// examined and served — through `acquire_dispatch_turn` and the reply
    /// actually being sent — then drop it.
    pub fn try_begin_examination(self: &Arc<Self>) -> Result<ExaminationPermit, ServeBusy> {
        self.examination_admission.clone().try_acquire_owned().map(ExaminationPermit).map_err(
            |_| ServeBusy {
                retry_after_ms: DEFAULT_RETRY_AFTER_MS,
                queue_depth: self
                    .examination_admission_capacity
                    .saturating_sub(self.examination_admission.available_permits())
                    as u32,
            },
        )
    }

    /// Waits for a fair turn (by least cumulative bytes granted so far --
    /// see `FairDispatchState`'s own doc comment) to actively work on a
    /// `cost_bytes`-sized request -- callers should acquire this BEFORE
    /// RESERVING byte credit (`try_admit`) or reading anything, so credit
    /// is never held hostage while a request is merely waiting its turn in
    /// the fairness queue; hold the returned guard for exactly as long as
    /// this request is being actively served (through the reply actually
    /// being sent), then drop it to let the next fairly-chosen waiter
    /// proceed.
    ///
    /// `cost_bytes` only needs to be COMPUTED before this call, not
    /// reserved -- callers already compute this exact estimate for
    /// `try_admit`'s own `bytes` parameter (a cheap, local `FileRecord`
    /// lookup or a pessimistic fallback constant, not a network round trip
    /// or a credit commitment), so passing it here first and to
    /// `try_admit` afterward does not reintroduce the "credit held
    /// hostage" problem this ordering exists to avoid.
    ///
    /// Returns `Err` immediately, with no wait at all, if the queue is
    /// already at `MAX_WAITING_MULTIPLE`'s cap -- callers should answer
    /// `Busy` on `Err` exactly like a `try_admit` denial, and are expected
    /// to additionally bound how long they wait on `Ok`'s future with their
    /// own `tokio::time::timeout` (safe to drop at any point -- see
    /// `FairDispatchQueue::acquire`'s own doc comment), since a fair turn
    /// eventually arriving is not the same guarantee as arriving before a
    /// requester's own response timeout.
    pub async fn acquire_dispatch_turn(
        self: &Arc<Self>,
        peer_id: &str,
        group_id: &str,
        cost_bytes: u64,
    ) -> Result<FairDispatchGuard, ServeBusy> {
        self.dispatch.acquire(peer_id, group_id, cost_bytes).await
    }

    /// Attempts to admit `bytes` of serving for `(peer_id, group_id)` against
    /// all three budgets at once. On success, returns a guard that
    /// releases all three when the caller is done (drop it once the reply
    /// has actually been sent, not merely once the bytes are read, so a slow
    /// send still counts against the budget it's consuming network capacity
    /// under).
    pub fn try_admit(
        self: &Arc<Self>,
        peer_id: &str,
        group_id: &str,
        bytes: u64,
    ) -> Result<ServeCreditGuard, ServeBusy> {
        self.credit.try_admit(peer_id, group_id, bytes)?;
        Ok(ServeCreditGuard {
            engine: self.clone(),
            peer_id: peer_id.to_string(),
            group_id: group_id.to_string(),
            bytes,
        })
    }

    /// Returns the `Arc<OnceCell>` for `(group_id, hash, expected_size)`,
    /// creating one if none is currently live -- same
    /// lazy-prune-on-insert shape as `SyncState::path_lock` (`index.rs`).
    /// The FIRST caller to actually run `.get_or_init(...)` on the
    /// returned cell does the real read/verify/compress/size-check
    /// (checked against ITS OWN `expected_size`);
    /// every concurrent caller for the SAME key gets the same `Arc` and
    /// therefore the same in-flight (or already-resolved) `OnceCell::
    /// get_or_init` future, which `tokio::sync::OnceCell` itself
    /// guarantees runs the initializer at most once and fans the result
    /// out to every awaiter.
    ///
    /// `expected_size` (the caller's own declared/reserved size for this
    /// block -- see `handle_block_request_with_credit`'s doc comment) is
    /// part of the KEY, not merely an input the first caller's initializer
    /// closure happens to use. Two requesters can disagree on
    /// `expected_size` for the identical hash if their own referencing
    /// records are inconsistent (one correctly sized, one corrupted/
    /// understated) -- coalescing across that boundary would let whichever
    /// caller wins `get_or_init` have its own size check run, while every
    /// other caller silently inherits that same "found" result WITHOUT its
    /// own size ever being checked. A requester whose own declared size was
    /// smaller than the real stored data would then be served more bytes
    /// than it reserved credit for, from a source that assumed the check
    /// already covered it (confirmed: this let a corrupted/understated
    /// record's request bypass its own credit reservation whenever it
    /// happened to coalesce behind a correctly-sized one).
    ///
    /// A negotiated-compression flag used to be part of this key too, for
    /// an analogous reason: two sessions could have negotiated compression
    /// differently with their own peers, and whichever request arrived
    /// first would otherwise have dictated the encoding for all of them.
    /// Compression is no longer negotiated -- every peer that reaches a
    /// session is the same protocol generation and understands both
    /// encodings -- so there is no longer a capability boundary for the key
    /// to keep apart, and every requester for one `(group, hash, size)`
    /// shares one read again.
    pub fn coalesce_cell(
        &self,
        group_id: &str,
        hash: &[u8],
        expected_size: Option<u64>,
    ) -> Arc<CoalesceCell> {
        let key = (group_id.to_string(), hash.to_vec(), expected_size);
        let mut cells = self.coalesce.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(cell) = cells.get(&key).and_then(Weak::upgrade) {
            return cell;
        }
        // A block is requested in bursts (every device wanting the same
        // new content at once) then never again -- prune stale weak
        // entries while the short registry lock is already held so a
        // stream of distinct hashes cannot grow this map without bound.
        cells.retain(|_, cell| cell.strong_count() > 0);
        let cell = Arc::new(OnceCell::new());
        cells.insert(key, Arc::downgrade(&cell));
        cell
    }
}

#[cfg(test)]
mod tests;
