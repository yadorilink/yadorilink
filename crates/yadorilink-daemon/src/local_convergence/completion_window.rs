//! The end of a window run's content writes, committed in batches.
//!
//! A pass settles a run of independent files concurrently. Each file still
//! writes its temp file, syncs it, renames it into place and syncs the
//! parent directory on its own; what it then has left is one small
//! transaction (the proof, `Present`, the intent clear and the obligation's
//! completion). Here the files of one run hand that transaction to a shared
//! queue instead of committing it themselves, and whichever of them is
//! polled when the queue is due commits everybody's in ONE SQLite
//! transaction, each item under its own savepoint and its own checks (see
//! `ReplicaCoordinator::close_content_writes`).
//!
//! The same collector also batches each file's open (`Participant::submit_open`),
//! which a file takes after its own path lock and before its write: it queues
//! an owned item and waits while still holding the lock and its root
//! operation, one transaction applies the queue with a savepoint and a root
//! check per item. That queue is due when every participant not yet past the
//! step has queued.
//!
//! # Who owns what
//!
//! A file's task awaits its completion's outcome while it still holds
//! everything it held while writing: its path lock, its root operation and
//! permit, its claim. The queue holds only owned data (the item and the
//! reply channel). The path lock matters most: between the rename and this
//! commit the row is `Hydrating` with its intent open, and a scan that
//! captured the path in that gap would author the disk's bytes as a new
//! local version that the later commit would then wrongly prove as the
//! received one. So the lock is released only after the outcome has arrived.
//!
//! A batch is committed on the blocking pool (`YADORILINK_RECEIVE_ASYNC_COMMIT`,
//! on unless `0`): whichever waiter finds the queue due takes the batch and
//! hands it to a job that owns the items, the reply channels and the commit,
//! and every future of the run, that one included, goes on being polled by
//! the one task that owns the run. The job replies to each waiter and wakes
//! them; nothing in it touches a waiter's guards.
//!
//! What keeps the guards alive until the commit is decided is the job fence:
//! when a batch is taken, every item's waiter learns its fence (under the
//! window's lock, so before any later drop can look at it), and a waiter
//! holds a `BatchWait` for as long as it holds its item's guards. Dropped
//! after its batch was taken (the run was cancelled, a sibling panicked), its
//! `Drop` blocks until the job has finished, however the job ends: the fence
//! completes last, also when the job panics or is dropped before it ran. A
//! future dropped while its item is still queued takes its guards with it and
//! closes its reply channel; the next flush discards every item whose channel
//! is closed instead of committing it, so nothing is committed for a file
//! that no longer holds its lock, and the drop and the take cannot interleave
//! because both happen on the run's task. A panic in the commit rolls its
//! transaction back and drops the reply channels, so each waiting file sees an
//! error. In all those cases the file is left as a crash after its
//! parent-directory sync would leave it: bytes on disk, row in flight, intent
//! and obligation open. With the knob off the flush runs in the flushing poll,
//! as before.
//!
//! # When it flushes
//!
//! - when every participant still in the run has queued (nobody else can
//!   arrive soon), which is immediately for a lone file;
//! - when the queue holds as many items as the run's concurrency limit;
//! - when the oldest item has waited `max_latency`.
//!
//! A participant is a run entry that is past its byte-budget wait and has
//! not finished; it leaves the window when its future ends, however it ends,
//! and that wakes the waiters to look again.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{oneshot, Notify};
use tokio::time::Instant;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_sqlite_runtime::JobFence;

use crate::replica_coordinator::{
    ContentWriteClose, ContentWriteCloseItem, OwnedContentWriteOpen, ReplicaCoordinator,
};

/// The longest an item waits for a batch to fill. Tunable; to be set from a
/// measurement.
pub(crate) const DEFAULT_MAX_LATENCY: Duration = Duration::from_millis(20);

const BATCH_COMPLETION_VAR: &str = "YADORILINK_RECEIVE_BATCH_COMPLETION";
const BATCH_OPEN_VAR: &str = "YADORILINK_RECEIVE_BATCH_OPEN";
const DEFERRED_FSYNC_VAR: &str = "YADORILINK_RECEIVE_DEFERRED_FSYNC";

/// How received files are flushed: once per batch instead of once per file.
/// `1` flushes every file with `F_FULLFSYNC` off the critical path and every
/// parent directory once; `2` (experimental) issues `fsync(2)` for each and a
/// single `F_FULLFSYNC`; `0` keeps the per-file flush. Unset means `1` on macOS
/// and off elsewhere; any other value is off. Every platform but Unix is off.
pub(crate) fn parse_deferred_flush(
    raw: Option<&str>,
) -> Option<yadorilink_local_storage::ReceivedFlushMode> {
    if !cfg!(unix) {
        return None;
    }
    match raw.map(str::trim) {
        Some("1") => Some(yadorilink_local_storage::ReceivedFlushMode::FullFsyncEach),
        Some("2") => Some(yadorilink_local_storage::ReceivedFlushMode::FsyncThenOneFullFsync),
        None if cfg!(target_os = "macos") => {
            Some(yadorilink_local_storage::ReceivedFlushMode::FullFsyncEach)
        }
        _ => None,
    }
}

pub(crate) fn deferred_flush_from_env() -> Option<yadorilink_local_storage::ReceivedFlushMode> {
    let raw = std::env::var(DEFERRED_FSYNC_VAR).ok();
    // A test build flushes per file unless the variable asks otherwise, so the
    // many tests that settle a received file by itself do not depend on the
    // host's default. The default itself is pinned through `parse_deferred_flush`.
    #[cfg(any(test, feature = "test-support"))]
    raw.as_ref()?;
    parse_deferred_flush(raw.as_deref())
}

/// A received file renamed into place whose flush the window's batch owes.
pub(crate) struct PendingFlush {
    pub(crate) group_id: String,
    pub(crate) path: String,
    pub(crate) out_path: std::path::PathBuf,
    /// The object renamed into `out_path`, which the barrier must find there.
    pub(crate) object: Option<yadorilink_local_storage::ObjectKey>,
    /// The sync root the file was written under, to prove again before the
    /// barrier decides that a file it cannot find is gone.
    pub(crate) root: std::path::PathBuf,
    /// The temp name the file was staged under; its ledger record is released
    /// once the file and its directory are flushed.
    pub(crate) tmp_path: std::path::PathBuf,
    pub(crate) ledger: yadorilink_sync_sqlite::MaterializationTempLedger,
    /// The fence the file's proof was published under, whose marked intent the
    /// flush clears; `None` when the close was refused and left no marker.
    pub(crate) marked_under: Option<i64>,
}

/// Whether file completions are batched: on unless the variable is `0`.
/// A/B knob for the measurement.
pub(crate) fn parse_batch_completion(raw: Option<&str>) -> bool {
    raw.map(str::trim) != Some("0")
}

pub(crate) fn batch_completion_from_env() -> bool {
    parse_batch_completion(std::env::var(BATCH_COMPLETION_VAR).ok().as_deref())
}

/// Whether the open of a file's write is batched: on unless the variable is
/// `0`. A/B knob for the measurement.
pub(crate) fn batch_open_from_env() -> bool {
    parse_batch_completion(std::env::var(BATCH_OPEN_VAR).ok().as_deref())
}

tokio::task_local! {
    static WINDOW: Arc<CompletionWindow>;
    static PARTICIPANT: Participant;
}

/// The window the calling future is a participant of, when it batches
/// completions.
pub(crate) fn current() -> Option<Arc<CompletionWindow>> {
    WINDOW.try_with(Arc::clone).ok().filter(|window| window.completions)
}

/// The calling future's membership, when its window batches the open of a
/// file's write: see [`Participant::submit_open`].
pub(crate) fn current_for_open() -> Option<Participant> {
    PARTICIPANT.try_with(Clone::clone).ok().filter(|participant| participant.0.window.opens)
}

/// Runs `future` as `participant` of `window`: everything it awaits sees them
/// through [`current`] and [`current_for_open`].
pub(crate) async fn within<F: Future>(
    window: Arc<CompletionWindow>,
    participant: Participant,
    future: F,
) -> F::Output {
    WINDOW.scope(window, PARTICIPANT.scope(participant, future)).await
}

type Reply<O> = oneshot::Sender<Result<O, PeerSessionError>>;

/// Set, under the window's lock, to the fence of the job that took the item
/// into a batch.
type BatchSlot = Arc<Mutex<Option<JobFence>>>;

struct Queued<I, O> {
    item: I,
    reply: Reply<O>,
    /// The fence of the batch this item was taken into, once it was.
    batch: BatchSlot,
}

/// Held by a waiter for as long as it holds the guards of its item (path
/// lock, root operation, claim, reservation). Dropping it blocks until the
/// job that took the item has decided the commit, so no guard is released
/// while the commit may still land on its behalf.
struct BatchWait(BatchSlot);

impl Drop for BatchWait {
    fn drop(&mut self) {
        let fence = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        // The fence's own waiter blocks until the job is done (and skips the
        // wait on a thread inside a write transaction).
        drop(fence.map(|fence| fence.waiter()));
    }
}

/// Wakes the window's waiters when dropped: after the replies (also on a
/// panic in the job, which drops them unsent).
struct WakeOnDrop(Arc<Notify>);

impl Drop for WakeOnDrop {
    fn drop(&mut self) {
        self.0.notify_waiters();
    }
}

type CommitFn<I, O> =
    Arc<dyn Fn(&[&I]) -> Result<Vec<Result<O, PeerSessionError>>, PeerSessionError> + Send + Sync>;

/// Items waiting for one kind of batch.
struct Queue<I, O> {
    queued: Vec<Queued<I, O>>,
    /// When the oldest queued item arrived.
    oldest: Option<Instant>,
}

impl<I, O> Default for Queue<I, O> {
    fn default() -> Self {
        Self { queued: Vec::new(), oldest: None }
    }
}

#[derive(Default)]
struct Inner {
    /// Joined and not yet left. Includes every queued item's file.
    participants: usize,
    /// Joined, not left, and not yet past the open step (queued or still to
    /// come). The open queue is due when all of them have queued.
    open_pending: usize,
    completions: Queue<ContentWriteCloseItem, ContentWriteClose>,
    opens: Queue<OwnedContentWriteOpen, i64>,
}

/// How long the window's files waited in each collector's queue (summed over
/// the files) and how long its batches took to commit, for the receive
/// budget's window timeline. Only written while the budget is armed.
#[derive(Default)]
struct CollectorTimes {
    waits_ns: [AtomicU64; 2],
    flushes_ns: [AtomicU64; 2],
}

fn collector_index(what: &str) -> usize {
    match what {
        "open" => crate::receive_diag::COLLECTOR_OPEN,
        _ => crate::receive_diag::COLLECTOR_CLOSE,
    }
}

/// Adds the time from its creation to its drop (however the wait ends,
/// including a cancel) to one collector's queue wait.
struct QueueWaitTimer<'a> {
    times: &'a CollectorTimes,
    index: usize,
    started: Option<std::time::Instant>,
}

impl Drop for QueueWaitTimer<'_> {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            let nanos = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            self.times.waits_ns[self.index].fetch_add(nanos, Ordering::Relaxed);
        }
    }
}

pub(crate) struct CompletionWindow {
    inner: Mutex<Inner>,
    times: Arc<CollectorTimes>,
    /// Woken when a flush finished or a participant left.
    wake: Arc<Notify>,
    cap: usize,
    max_latency: Duration,
    /// Whether a batch is committed on the blocking pool (the flushing
    /// future keeps polling, the run's other files keep going) or inline in
    /// the flushing poll.
    async_commit: bool,
    /// Which steps batch (the others run per file, as without a window).
    completions: bool,
    opens: bool,
    /// How the window's received files are flushed once the run is over, when
    /// they are not flushed one by one.
    deferred_flush: Option<yadorilink_local_storage::ReceivedFlushMode>,
    flush_pending: Mutex<Vec<PendingFlush>>,
}

struct Membership {
    window: Arc<CompletionWindow>,
    /// Set once the file is past the open step: it queued and got its
    /// outcome, or it left.
    past_open: AtomicBool,
}

/// A run entry's membership of its window; leaving is the last handle
/// dropping (the entry's future and its task-local one end together).
#[derive(Clone)]
pub(crate) struct Participant(Arc<Membership>);

impl Drop for Membership {
    fn drop(&mut self) {
        {
            let mut inner = self.window.lock();
            inner.participants = inner.participants.saturating_sub(1);
            if !self.past_open.swap(true, Ordering::SeqCst) {
                inner.open_pending = inner.open_pending.saturating_sub(1);
            }
        }
        self.window.wake.notify_waiters();
    }
}

impl Participant {
    /// Queues the file's open (the statements that move its row to in flight,
    /// open its intent and bump its fence) and returns once its transaction
    /// has been decided, with the fence value or that item's error. The
    /// caller keeps every guard it holds for the file (its path lock, the
    /// lane's root operation, the row's own operation) until this returns,
    /// and writes no byte before it has: the row of a path moves only at the
    /// batch's commit.
    pub(crate) async fn submit_open(
        &self,
        coordinator: &Arc<ReplicaCoordinator>,
        item: OwnedContentWriteOpen,
    ) -> Result<i64, PeerSessionError> {
        let window = &self.0.window;
        let coordinator = Arc::clone(coordinator);
        let result = window
            .submit_to(
                |inner| &mut inner.opens,
                |inner| inner.open_pending,
                item,
                "open",
                Arc::new(move |items: &[&OwnedContentWriteOpen]| {
                    crate::receive_diag::record_open_batch(items.len());
                    coordinator.open_content_writes(items)
                }),
            )
            .await;
        // Past the step whatever happened; the others stop waiting for it.
        {
            let mut inner = window.lock();
            if !self.0.past_open.swap(true, Ordering::SeqCst) {
                inner.open_pending = inner.open_pending.saturating_sub(1);
            }
        }
        window.wake.notify_waiters();
        result
    }
}

impl CompletionWindow {
    #[cfg(test)]
    pub(crate) fn new(cap: usize, max_latency: Duration) -> Arc<Self> {
        Self::with_steps(cap, max_latency, true, true, true)
    }

    #[cfg(test)]
    pub(crate) fn with_steps(
        cap: usize,
        max_latency: Duration,
        completions: bool,
        opens: bool,
        async_commit: bool,
    ) -> Arc<Self> {
        Self::with_deferred_flush(cap, max_latency, completions, opens, async_commit, None)
    }

    pub(crate) fn with_deferred_flush(
        cap: usize,
        max_latency: Duration,
        completions: bool,
        opens: bool,
        async_commit: bool,
        deferred_flush: Option<yadorilink_local_storage::ReceivedFlushMode>,
    ) -> Arc<Self> {
        Arc::new(Self {
            // Deferring needs the batched close: that is where the intent stays open.
            deferred_flush: deferred_flush.filter(|_| completions),
            flush_pending: Mutex::new(Vec::new()),
            inner: Mutex::new(Inner::default()),
            times: Arc::default(),
            wake: Arc::new(Notify::new()),
            cap: cap.max(1),
            max_latency,
            async_commit,
            completions,
            opens,
        })
    }

    /// How this window's received files are flushed after the run, when the
    /// writers defer their own flush.
    pub(crate) fn deferred_flush_mode(
        &self,
    ) -> Option<yadorilink_local_storage::ReceivedFlushMode> {
        self.deferred_flush
    }

    pub(crate) fn note_flush_pending(&self, pending: PendingFlush) {
        self.flush_pending.lock().unwrap_or_else(|p| p.into_inner()).push(pending);
    }

    /// Records that the close of the file renamed in at `out_path` published its
    /// proof under `mutation_generation`, so the barrier clears its marked intent.
    pub(crate) fn mark_flush_published(
        &self,
        out_path: &std::path::Path,
        mutation_generation: i64,
    ) {
        let mut pending = self.flush_pending.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = pending.iter_mut().rev().find(|entry| entry.out_path == out_path) {
            entry.marked_under = Some(mutation_generation);
        }
    }

    /// Everything the run's writers left unflushed, for the batch barrier.
    pub(crate) fn take_flush_pending(&self) -> Vec<PendingFlush> {
        std::mem::take(&mut *self.flush_pending.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The queue waits and the batch commit times of this window so far, per
    /// collector (open, close), in nanoseconds.
    pub(crate) fn collector_times(&self) -> ([u64; 2], [u64; 2]) {
        (
            std::array::from_fn(|index| self.times.waits_ns[index].load(Ordering::Relaxed)),
            std::array::from_fn(|index| self.times.flushes_ns[index].load(Ordering::Relaxed)),
        )
    }

    pub(crate) fn join(self: &Arc<Self>) -> Participant {
        {
            let mut inner = self.lock();
            inner.participants += 1;
            inner.open_pending += 1;
        }
        Participant(Arc::new(Membership {
            window: self.clone(),
            past_open: AtomicBool::new(false),
        }))
    }

    /// Lets the run's other entries that are about to start join before this
    /// one goes on. The entries of a run are polled one after the other and
    /// their database calls are synchronous, so without this the first entry
    /// could reach the open step before the second had joined, see itself
    /// as the only participant and flush alone. A no-op unless the open step
    /// is batched.
    pub(crate) async fn let_siblings_join(&self) {
        if self.opens {
            tokio::task::yield_now().await;
        }
    }

    /// Queues `item` and returns once its transaction has committed (or
    /// failed, or was refused), with that outcome. The caller keeps every
    /// guard it holds for the file until this returns.
    pub(crate) async fn submit(
        &self,
        coordinator: &Arc<ReplicaCoordinator>,
        item: ContentWriteCloseItem,
    ) -> Result<ContentWriteClose, PeerSessionError> {
        let coordinator = Arc::clone(coordinator);
        self.submit_to(
            |inner| &mut inner.completions,
            |inner| inner.participants,
            item,
            "completion",
            Arc::new(move |items: &[&ContentWriteCloseItem]| {
                crate::receive_diag::record_completion_batch(items.len());
                coordinator.close_content_writes(items)
            }),
        )
        .await
    }

    /// The one collector both steps share: queue `item` in the queue `queue`
    /// picks, then take part in flushing it until the outcome is there.
    /// `waiting_for` is how many items must be queued for the batch to be due
    /// without waiting for the deadline.
    ///
    /// The future holds a [`BatchWait`] while its item is queued or in a
    /// batch: dropped (the run was cancelled) after its batch was taken, it
    /// blocks until that batch's commit is decided, so the guards the caller
    /// holds for this item outlive the commit.
    async fn submit_to<I, O>(
        &self,
        queue: fn(&mut Inner) -> &mut Queue<I, O>,
        waiting_for: fn(&Inner) -> usize,
        item: I,
        what: &'static str,
        commit: CommitFn<I, O>,
    ) -> Result<O, PeerSessionError>
    where
        I: Send + 'static,
        O: Send + 'static,
    {
        let (reply, mut outcome) = oneshot::channel();
        let batch_slot = BatchSlot::default();
        let _batch_wait = BatchWait(batch_slot.clone());
        let _queue_wait = QueueWaitTimer {
            times: &self.times,
            index: collector_index(what),
            started: crate::receive_diag::clock(),
        };
        {
            let mut inner = self.lock();
            let queue = queue(&mut inner);
            queue.queued.push(Queued { item, reply, batch: batch_slot });
            queue.oldest.get_or_insert_with(Instant::now);
        }
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some((batch, fence)) = self.take_if_due(queue, waiting_for) {
                self.flush(batch, fence, what, &commit);
            }
            match outcome.try_recv() {
                Ok(result) => return result,
                Err(oneshot::error::TryRecvError::Closed) => {
                    return Err(PeerSessionError::CorruptState(format!(
                        "the batched {what} of this file was abandoned before it committed; \
                         the file stays as it was for recovery"
                    )));
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            let deadline = queue(&mut self.lock()).oldest.map(|oldest| oldest + self.max_latency);
            match deadline {
                Some(deadline) => {
                    tokio::select! {
                        () = &mut notified => {}
                        () = tokio::time::sleep_until(deadline) => {}
                    }
                }
                None => notified.await,
            }
        }
    }

    /// The queued items when the policy says to commit them now, with the
    /// fence of the commit they are taken for (every item's waiter learns it
    /// under this lock). Items whose waiter has gone are dropped here,
    /// uncommitted: their file no longer holds the lock that makes
    /// committing them safe.
    fn take_if_due<I, O>(
        &self,
        queue: fn(&mut Inner) -> &mut Queue<I, O>,
        waiting_for: fn(&Inner) -> usize,
    ) -> Option<(Vec<Queued<I, O>>, JobFence)> {
        let mut inner = self.lock();
        let needed = waiting_for(&inner);
        let queue = queue(&mut inner);
        queue.queued.retain(|queued| !queued.reply.is_closed());
        if queue.queued.is_empty() {
            queue.oldest = None;
            return None;
        }
        let due = queue.queued.len() >= needed
            || queue.queued.len() >= self.cap
            || queue.oldest.is_some_and(|oldest| Instant::now() >= oldest + self.max_latency);
        if !due {
            return None;
        }
        queue.oldest = None;
        let fence = JobFence::new();
        let batch = std::mem::take(&mut queue.queued);
        for queued in &batch {
            *queued.batch.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(fence.clone());
        }
        Some((batch, fence))
    }

    /// Commits `batch` in one transaction and hands each file its outcome:
    /// on the blocking pool (this call returns at once and the file futures
    /// keep being polled; the job sends the replies and wakes the waiters),
    /// or inline in this poll.
    ///
    /// Inline, no future of the run can be dropped while it runs. Offloaded,
    /// the job owns the items, the replies and the commit, and takes nothing
    /// from the waiters; what keeps their guards alive until it has decided
    /// is each waiter's [`BatchWait`] on `fence`, which the job completes
    /// last (also when it panics, or is dropped before it ran).
    fn flush<I, O>(
        &self,
        batch: Vec<Queued<I, O>>,
        fence: JobFence,
        what: &'static str,
        commit: &CommitFn<I, O>,
    ) where
        I: Send + 'static,
        O: Send + 'static,
    {
        let completion = fence.completion();
        let wake = WakeOnDrop(self.wake.clone());
        let commit = commit.clone();
        let times = self.times.clone();
        let job = move || {
            // Dropped last, after the replies and the wake.
            let _completion = completion;
            let _scope = _completion.enter();
            _completion.set_items(batch.len());
            let _wake = wake;
            let started = crate::receive_diag::clock();
            Self::run_commit(batch, what, &commit);
            if let Some(started) = started {
                let nanos = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                times.flushes_ns[collector_index(what)].fetch_add(nanos, Ordering::Relaxed);
            }
        };
        if self.async_commit {
            drop(tokio::task::spawn_blocking(job));
        } else {
            job();
        }
    }

    fn run_commit<I, O>(batch: Vec<Queued<I, O>>, what: &str, commit: &CommitFn<I, O>) {
        let results = {
            let items: Vec<&I> = batch.iter().map(|queued| &queued.item).collect();
            commit(&items)
        };
        match results {
            Ok(results) => {
                for (queued, result) in batch.into_iter().zip(results) {
                    let _ = queued.reply.send(result);
                }
            }
            Err(error) => {
                let message = error.to_string();
                for queued in batch {
                    let _ = queued.reply.send(Err(PeerSessionError::CorruptState(format!(
                        "the batched {what} transaction failed: {message}"
                    ))));
                }
            }
        }
    }
}

/// Whether disk still holds the bytes an item was verified against, given
/// whether the object's identity is unchanged since that verification and
/// whether that identity would show an in-place rewrite that kept the length
/// and restored the modification time (`FileIdentity::in_place_rewrite_visible`).
/// When it would not, an unchanged identity proves nothing about the bytes, so
/// they are compared themselves.
pub(crate) fn verified_bytes_still_on_disk(
    identity_unchanged: bool,
    rewrite_visible: bool,
    bytes_match: impl FnOnce() -> bool,
) -> bool {
    identity_unchanged && (rewrite_visible || bytes_match())
}
