//! The blocking-work counter behind `RootLease`, kept free of lease and filesystem types so the
//! Shuttle explorer (`xtask/tests/shuttle_races.rs`) can compile this exact file with `#[path]`
//! against a scheduler-aware `sync_facade` and explore the real code.
//!
//! Invariant: a waiter registers for the wake-up before it reads the count, so the release that
//! takes the count to zero is never missed, and a waiter sees zero only after every hold has been
//! released.
//!
//! This file may only depend on `crate::sync_facade`.

use crate::sync_facade::{AtomicI64, Notify, Ordering, Registration};

#[derive(Default)]
pub(crate) struct BlockingWork {
    held: AtomicI64,
    notify: Notify,
}

impl BlockingWork {
    pub(crate) fn acquire(&self) {
        self.held.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn release(&self) {
        if self.held.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.notify.notify_waiters();
        }
    }

    /// `None` once no hold remains. Otherwise a registration that is woken by the release that
    /// brings the count to zero; the caller waits on it and asks again.
    pub(crate) fn register_unless_released(&self) -> Option<Registration<'_>> {
        let registration = self.notify.register();
        if self.held.load(Ordering::SeqCst) == 0 {
            return None;
        }
        Some(registration)
    }
}
