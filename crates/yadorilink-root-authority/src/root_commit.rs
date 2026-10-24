//! `RootLease`/`LinkOperation`: the capability every daemon-originated local
//! filesystem/index/native state/materialization-state mutation must hold, and the
//! RAII guard that proves it for an operation's *whole* duration.
//!
//! # Why a held guard, not a momentary check
//!
//! An earlier version of this module defined a `RootAuthority` trait with a
//! single `fn verify(&self) -> Result<(), RootAuthorityError>` method, and
//! `RootCommitPermit::verify()` simply called it. That is a **check**, not a
//! **lease**: nothing stopped a caller from calling `verify()`, getting
//! `Ok`, and then taking real, unbounded time (a multi-block filesystem
//! reconstruct, a chunked scan) before its actual commit — during which
//! `stop_link_watch`'s `wait_drained` could observe no admitted operation
//! (the daemon-side `RootAuthority` impl minted and dropped its own
//! admission guard *inside* `verify()`, immediately, not for the caller's
//! whole operation) and proceed to release the sync-root OS lock while the
//! caller's write was still in flight. This is precisely K15's shape,
//! reopened by a check-based design no matter how many call sites call it.
//!
//! `RootLease`/`LinkOperation` closes this structurally: [`RootLease::
//! begin_operation`] returns a [`LinkOperation`] the caller MUST hold from
//! before its first filesystem write through its last DB/native commit — not
//! drop immediately. [`RootCommitPermit`] can only be constructed from a
//! live `&LinkOperation` ([`LinkOperation::permit`]), so a caller with a
//! permit in hand is, by construction (the borrow checker, not a runtime
//! check), still holding the same admission slot `wait_drained` waits to
//! drain. There is no way to call `.verify()` on a permit whose backing
//! `LinkOperation` has already dropped: that permit cannot exist.
//!
//! # Who owns a lease
//!
//! This crate defines `RootLease` and owns its mechanism (the
//! [`crate::sync_root_lock::SyncRootLock`] it wraps, and its own
//! stop/drain gate), but a lease's *lifecycle* — when a link starts, stops,
//! or restarts, i.e. when an `Arc<RootLease>` is actually constructed and
//! handed to callers — is `yadorilink-daemon`'s `link_manager` territory.
//! One `RootLease` is constructed per link, immediately after that link's
//! `SyncRootLock` is acquired, and shared (via `Arc`) by every subsystem
//! that mutates through this link: the local-change processor, the peer
//! session (through an injected per-group lookup), the periodic and
//! startup repair passes, the targeted-flush handle, and the disk-reconcile
//! backstop sweep. `stop_link_watch`/`graceful_shutdown` call
//! [`RootLease::begin_stopping`] then await [`RootLease::wait_drained`]
//! before dropping the lease (and, with it, the `SyncRootLock` — releasing
//! the OS-level lock only once every in-flight `LinkOperation` has
//! genuinely finished).
//!
//! Test code that has no real link lifecycle uses [`RootCommitPermit::
//! for_tests`], which is backed by one process-lifetime, always-succeeding
//! `RootLease`/`LinkOperation` pair. This is deliberately NOT reachable
//! from non-test code: there is no production code path that can construct
//! a permit without going through a real `RootLease::begin_operation`.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

use crate::blocking_work_core::BlockingWork;
use crate::error::RootAuthorityError;
use crate::sync_root_lock::SyncRootLock;
use crate::writer_lease::WriterLease;

/// One linked folder's root-mutation capability: the `SyncRootLock` proving
/// single-process ownership of this root, this link's group id and startup
/// generation, and the stop/drain gate every [`LinkOperation`] admits
/// through. Shared (`Arc<RootLease>`) by every subsystem that can mutate
/// this link's filesystem/index/native state/materialization state — see this
/// module's own doc for the full list.
pub struct RootLease {
    /// `None` only for [`RootLease::for_tests`] — see that constructor's
    /// own doc for why test code has no real `SyncRootLock` to hold.
    root_lock: Option<SyncRootLock>,
    group_id: String,
    generation: u64,
    stopping: AtomicBool,
    /// A pause that can be lifted: admission is refused like `stopping`, but
    /// [`RootLease::end_quiesce`] reopens it. Used to bring the link to a
    /// safe point before a requested stop and to give up on that stop
    /// without leaving the link refusing work.
    quiescing: AtomicBool,
    active: AtomicI64,
    notify: Notify,
    /// Blocking-pool work that cannot be cancelled and still owns the processor (and so this
    /// lease) after its task is aborted; see [`RootLease::hold_blocking_work`].
    blocking_work: Arc<BlockingWork>,
    /// Fence for hosts without a daemon; `None` on the desktop, where the root lock is the
    /// ownership proof. See [`RootLease::with_writer_lease`].
    writer_lease: Option<Arc<WriterLease>>,
}

/// Proof that uncancellable blocking-pool work is still running for a lease. Dropping it (after
/// the work has let go of everything else it owns) is what lets [`RootLease::wait_blocking_work_released`]
/// return. Does not itself keep the lease, or its root lock, alive.
pub struct BlockingWorkHold {
    work: Arc<BlockingWork>,
}

impl Drop for BlockingWorkHold {
    fn drop(&mut self) {
        self.work.release();
    }
}

impl RootLease {
    /// Constructs a lease around an already-acquired `SyncRootLock`. Callers
    /// (`yadorilink-daemon::link_manager::start_link_watch_inner`) acquire
    /// the lock first and pass it in here immediately — there is no
    /// constructor that lets production code skip having a real lock.
    pub fn new(root_lock: SyncRootLock, group_id: String, generation: u64) -> Self {
        Self {
            root_lock: Some(root_lock),
            group_id,
            generation,
            stopping: AtomicBool::new(false),
            quiescing: AtomicBool::new(false),
            active: AtomicI64::new(0),
            notify: Notify::new(),
            blocking_work: Arc::default(),
            writer_lease: None,
        }
    }

    /// Adds a writer-lease fence: every admission and every permit check then also requires
    /// the lease to still be this writer's ([`WriterLease::verify`]), so a late writer whose
    /// lease was taken over is refused at commit.
    #[must_use]
    pub fn with_writer_lease(mut self, lease: Arc<WriterLease>) -> Self {
        self.writer_lease = Some(lease);
        self
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn root(&self) -> Option<&Path> {
        self.root_lock.as_ref().map(SyncRootLock::root)
    }

    /// Admits one operation unless this lease is stopping (`NotFound`: the link is going away
    /// for good) or paused for a safe stop (`Quiescing`: temporary; the caller keeps its work and
    /// retries, and must never read the refusal as "nothing left to do"), and
    /// re-verifies the underlying `SyncRootLock` still names the same
    /// physical object it was acquired against (closes the unlink-and-
    /// recreate root-swap hazard `SyncRootLock::verify_still_owns`'s own
    /// doc describes). The caller MUST hold the returned [`LinkOperation`]
    /// for this operation's whole duration — from before its first
    /// filesystem write through its last DB/native commit — not drop it
    /// immediately after admission. Holding it for less than that
    /// reintroduces exactly the gap this module exists to close.
    pub fn begin_operation(&self) -> Result<LinkOperation<'_>, RootAuthorityError> {
        self.admit(true)
    }

    /// Admission for recording that a path needs capturing (the dirty-path journal), which is
    /// admitted while the lease is paused for a safe stop and refused only once it is stopping.
    /// A change observed during a pause must reach the journal before anything can refuse it, so
    /// that when the pause is lifted again the journal redrive finds it. The caller still holds
    /// the returned operation for the write's duration, like any other.
    pub fn begin_journal_operation(&self) -> Result<LinkOperation<'_>, RootAuthorityError> {
        self.admit(false)
    }

    /// Whether the lease is being torn down for good (as opposed to paused). Code that treats a
    /// refusal as "this link is going away, the next start's rescan covers it" must ask this, not
    /// merely observe that admission was refused.
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    fn admit(&self, respect_pause: bool) -> Result<LinkOperation<'_>, RootAuthorityError> {
        if let Some(refusal) = self.refusal(respect_pause) {
            return Err(refusal);
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        // Re-check: `begin_stopping` (or `begin_quiesce`) may have run between the load above and
        // this increment. Without this, our own count could make `wait_drained` wait for an
        // operation this call is about to refuse to start.
        if let Some(refusal) = self.refusal(respect_pause) {
            self.release();
            return Err(refusal);
        }
        if let Some(root_lock) = &self.root_lock {
            if let Err(e) = root_lock.verify_still_owns() {
                self.release();
                return Err(e);
            }
        }
        if let Some(writer) = &self.writer_lease {
            if let Err(e) = writer.verify() {
                self.release();
                return Err(e);
            }
        }
        Ok(LinkOperation { lease: self })
    }

    fn refusal(&self, respect_pause: bool) -> Option<RootAuthorityError> {
        if self.stopping.load(Ordering::SeqCst) {
            return Some(Self::stopping_error(&self.group_id));
        }
        if respect_pause && self.quiescing.load(Ordering::SeqCst) {
            return Some(RootAuthorityError::Quiescing(format!(
                "link for group {} is paused for a safe stop; retry once it resumes",
                self.group_id
            )));
        }
        None
    }

    fn stopping_error(group_id: &str) -> RootAuthorityError {
        RootAuthorityError::NotFound(format!(
            "link for group {group_id} is stopping or stopped; refusing a new root-commit \
             operation"
        ))
    }

    /// How many operations are admitted right now. For tests that must show
    /// a code path holds none (a second `begin_operation` succeeding proves
    /// nothing: operations are counted, not exclusive).
    #[cfg(any(test, feature = "test-support"))]
    pub fn active_operations(&self) -> i64 {
        self.active.load(Ordering::SeqCst)
    }

    fn release(&self) {
        if self.active.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.notify.notify_waiters();
        }
    }

    /// Refuses every new `begin_operation` call from this point on.
    /// Already-admitted `LinkOperation`s are unaffected and must still be
    /// allowed to finish — see [`RootLease::wait_drained`].
    pub fn begin_stopping(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// Refuses every new `begin_operation` call until [`RootLease::end_quiesce`],
    /// exactly as `begin_stopping` does but reversibly. Already-admitted
    /// operations finish; [`RootLease::wait_drained`] waits for them. A lease
    /// that is stopping stays stopped whatever happens to the pause.
    pub fn begin_quiesce(&self) {
        self.quiescing.store(true, Ordering::SeqCst);
    }

    /// Reopens admission after [`RootLease::begin_quiesce`].
    pub fn end_quiesce(&self) {
        self.quiescing.store(false, Ordering::SeqCst);
    }

    /// Waits until every `LinkOperation` admitted before (or racing, per
    /// `begin_operation`'s own re-check) `begin_stopping` has dropped.
    /// Callers must call `begin_stopping` first; awaiting this without
    /// having done so waits for a count that new operations can still keep
    /// nonzero forever.
    pub async fn wait_drained(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Technically redundant for `notify_waiters` specifically (a
            // `Notified` future is guaranteed to receive wakeups from
            // `notify_waiters()` as soon as it is created), but costs
            // nothing and keeps this loop correct even if this ever moves
            // to `notify_one`.
            notified.as_mut().enable();
            if self.active.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Registers uncancellable blocking-pool work (a `spawn_blocking` scan) that owns this lease
    /// through its processor. Aborting the task that awaits such work does not stop it, so
    /// [`RootLease::wait_drained`] (which only sees admitted operations, and only while a commit is
    /// in flight) cannot tell the root is still in use. Take the hold on the async side before
    /// spawning, move it into the closure, and drop it after every other clone of the lease the
    /// closure owns, so that when [`RootLease::wait_blocking_work_released`] returns the closure
    /// no longer owns the lease. Unlike an operation it does not delay a safe-stop pause.
    pub fn hold_blocking_work(&self) -> BlockingWorkHold {
        self.blocking_work.acquire();
        BlockingWorkHold { work: self.blocking_work.clone() }
    }

    /// Waits until every [`BlockingWorkHold`] has been dropped. Call after the tasks that
    /// spawn such work have been awaited, so no new hold can appear.
    pub async fn wait_blocking_work_released(&self) {
        while let Some(registration) = self.blocking_work.register_unless_released() {
            registration.wait().await;
        }
    }

    /// A lease with no real `SyncRootLock`, an always-empty stop/drain gate
    /// starting point, and a stable `"test-group"` id — for tests that
    /// exercise `SyncState`'s own mutation behavior and have no real link
    /// lifecycle to check against. Kept in this crate (not duplicated per
    /// test module) so every test using it shares one obviously-inert
    /// instance. See [`RootCommitPermit::for_tests`] for the ergonomic,
    /// no-ceremony entry point most test code should actually call.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests() -> Self {
        Self {
            root_lock: None,
            group_id: "test-group".to_string(),
            generation: 0,
            stopping: AtomicBool::new(false),
            quiescing: AtomicBool::new(false),
            active: AtomicI64::new(0),
            notify: Notify::new(),
            blocking_work: Arc::default(),
            writer_lease: None,
        }
    }
}

/// RAII proof of admission against one [`RootLease`], held by its caller
/// for an operation's whole duration. See this module's own doc for why
/// that duration (not a momentary check) is what makes
/// [`RootCommitPermit::verify`] trustworthy.
pub struct LinkOperation<'a> {
    lease: &'a RootLease,
}

impl Drop for LinkOperation<'_> {
    fn drop(&mut self) {
        self.lease.release();
    }
}

impl<'a> LinkOperation<'a> {
    pub fn group_id(&self) -> &str {
        self.lease.group_id()
    }

    pub fn lease(&self) -> &'a RootLease {
        self.lease
    }

    /// Re-verifies root identity right now (one `SyncRootLock::
    /// verify_still_owns` call — cheap, but not free) — for an operation
    /// that itself spans meaningfully long real I/O between `begin_
    /// operation` and its own commit, calling this again immediately
    /// before the commit closes the same unlink-and-recreate window a
    /// single check at admission cannot. `RootCommitPermit::verify` calls
    /// this on the caller's behalf; most callers never need to call it
    /// directly.
    fn reverify(&self) -> Result<(), RootAuthorityError> {
        if let Some(root_lock) = &self.lease.root_lock {
            root_lock.verify_still_owns()?;
        }
        match &self.lease.writer_lease {
            Some(writer) => writer.verify(),
            None => Ok(()),
        }
    }

    /// Mints a [`RootCommitPermit`] borrowing this operation. Cheap to call
    /// repeatedly — every gated `SyncState`/materialization call along this
    /// operation's path takes its own fresh permit from the same held
    /// `LinkOperation`, rather than the permit being stored anywhere.
    pub fn permit(&self) -> RootCommitPermit<'_> {
        RootCommitPermit { op: self }
    }
}

/// A capability proving [`LinkOperation::permit`] was called against a
/// still-live `LinkOperation` — see this module's own doc for why holding
/// one is, by construction, proof of live admission, not merely evidence
/// that admission held at some earlier instant.
pub struct RootCommitPermit<'a> {
    op: &'a LinkOperation<'a>,
}

impl<'a> RootCommitPermit<'a> {
    /// Called by every gated `SyncState`/materialization function, inside
    /// its own write transaction, immediately before commit. Re-verifies
    /// root identity (see `LinkOperation::reverify`'s doc) — NOT a
    /// liveness/fence check, since holding the live `&LinkOperation` this
    /// permit borrows from already IS the fence-liveness proof: the type
    /// system cannot construct this permit from an operation that has
    /// already been dropped (and therefore already released its gate
    /// slot), so there is nothing left for a runtime check to race.
    pub fn verify(&self) -> Result<(), RootAuthorityError> {
        self.op.reverify()
    }

    /// This permit's root-identity check, owned, for a commit that runs in a
    /// transaction shared with other operations and so cannot borrow the
    /// permit. It checks exactly what [`Self::verify`] checks. The operation
    /// the permit borrows must stay held until that commit has finished: the
    /// stop fence is the operation's, not the check's.
    pub fn owned_check(&self) -> OwnedPermitCheck {
        OwnedPermitCheck(
            self.op.lease.root_lock.as_ref().map(SyncRootLock::identity_check),
            self.op.lease.writer_lease.clone(),
        )
    }
}

/// See [`RootCommitPermit::owned_check`].
#[derive(Debug, Clone)]
pub struct OwnedPermitCheck(
    Option<crate::sync_root_lock::RootIdentityCheck>,
    Option<Arc<WriterLease>>,
);

impl OwnedPermitCheck {
    pub fn verify(&self) -> Result<(), RootAuthorityError> {
        if let Some(check) = &self.0 {
            check.verify()?;
        }
        match &self.1 {
            Some(writer) => writer.verify(),
            None => Ok(()),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl RootCommitPermit<'static> {
    /// A permit backed by one process-lifetime, always-succeeding
    /// `RootLease`/`LinkOperation` pair — the ergonomic, no-ceremony entry
    /// point for test code that doesn't care about link lifecycle. Every
    /// call shares the SAME leaked `LinkOperation` (constructed exactly
    /// once via `OnceLock`), so this leaks one admission slot for the
    /// whole process rather than one per call.
    pub fn for_tests() -> Self {
        use std::sync::OnceLock;
        static LEASE: OnceLock<RootLease> = OnceLock::new();
        static OPERATION: OnceLock<LinkOperation<'static>> = OnceLock::new();
        let lease = LEASE.get_or_init(RootLease::for_tests);
        let op = OPERATION
            .get_or_init(|| lease.begin_operation().expect("a fresh for_tests lease never stops"));
        op.permit()
    }
}

#[cfg(test)]
mod tests;
