//! Wakes the Convergence Engine's scheduler loop promptly whenever a
//! `materialization_jobs` row becomes newly runnable (a fresh `Pending`
//! enqueue). One process-wide `Notify` rather than a per-`(group,path)`
//! registry: the engine's own poll (`materialization_claim_runnable_jobs`)
//! is cheap and indexed, so a coarse "something changed, re-poll
//! everything" wake is sufficient — unlike the path-lock/startup-readiness
//! registries, nothing here needs a specific waiter to be told a specific
//! outcome, so no generation-guarding is needed. `notify_materialization_wake`
//! calls `notify_one` (not `notify_waiters`) specifically because there is
//! exactly one consumer (the engine's own scheduler loop) and `notify_one`
//! stores a permit for the next waiter even when called with nobody
//! currently waiting — see that method's own doc comment. Even so, callers
//! must still pair `materialization_wake_notified` with a fallback timeout
//! in a `select!` (spurious extra polls are harmless; this is a coarse
//! "something changed" signal, not a promise tied to any specific job).

pub struct MaterializationWake {
    notify: tokio::sync::Notify,
}

impl Default for MaterializationWake {
    fn default() -> Self {
        Self::new()
    }
}

impl MaterializationWake {
    pub fn new() -> Self {
        Self { notify: tokio::sync::Notify::new() }
    }

    /// Wakes the Convergence Engine's scheduler loop — called after
    /// enqueuing a `Pending` job so the engine notices promptly rather than
    /// waiting for its own fallback poll interval. Deliberately `notify_one`,
    /// not `notify_waiters`: exactly one scheduler loop ever consumes this,
    /// and `notify_one` stores a permit for the next `notified().await` when
    /// no waiter is currently registered, whereas `notify_waiters` only wakes
    /// *already-registered* waiters and loses the signal entirely if none are
    /// waiting at the moment of the call — a real missed-wakeup gap for a
    /// loop that spends most of its time somewhere other than inside
    /// `notified().await` (e.g. running `run_once`). The fallback poll
    /// interval in `select!` still bounds the damage of any wakeup this
    /// doesn't catch, but there's no reason to accept that gap when
    /// `notify_one` closes it for free.
    pub fn notify_materialization_wake(&self) {
        self.notify.notify_one();
    }

    /// Resolves once `notify_materialization_wake` is called (or spuriously
    /// — callers must always pair this with a fallback timeout in a
    /// `select!`, not rely on it alone; see this type's own doc comment for
    /// why no generation-guarding is needed here).
    pub async fn materialization_wake_notified(&self) {
        self.notify.notified().await;
    }
}
