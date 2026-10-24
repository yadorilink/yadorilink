//! The sync primitives of the section the Shuttle explorer compiles from this crate by
//! `#[path]` (see `blocking_work_core`). Here they are `std` and `tokio`;
//! `xtask/tests/shuttle_races.rs` defines a module of the same name backed by Shuttle's
//! scheduler-aware types.

use std::pin::Pin;

pub(crate) use std::sync::atomic::{AtomicI64, Ordering};

/// Wake-up for waiters that registered before they checked a condition.
#[derive(Default)]
pub(crate) struct Notify(tokio::sync::Notify);

/// A waiter already registered with a [`Notify`]: a `notify_waiters` after `register` returned
/// wakes it, even if it is not awaited yet.
pub(crate) struct Registration<'a>(Pin<Box<tokio::sync::futures::Notified<'a>>>);

impl Notify {
    pub(crate) fn notify_waiters(&self) {
        self.0.notify_waiters();
    }

    pub(crate) fn register(&self) -> Registration<'_> {
        let mut notified = Box::pin(self.0.notified());
        notified.as_mut().enable();
        Registration(notified)
    }
}

impl Registration<'_> {
    pub(crate) async fn wait(self) {
        self.0.await;
    }
}
