//! The steps the namespace operations actually took, in order, for the model in
//! [`super::model`]. Recorded per thread; compiled to nothing without
//! `test-support`.
#![cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]

use std::path::PathBuf;

/// One file system step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A new file or directory exists (not yet durable by itself).
    Create { path: PathBuf, dir: bool },
    /// The file's content was flushed.
    FlushFile { path: PathBuf },
    /// A durable move: `write_through` says the move itself is on disk when it
    /// returns, which holds on Windows. On Unix the move is made durable by the
    /// directory syncs that follow; the flag is `true` there too so one trace
    /// can be replayed under either profile.
    Move { from: PathBuf, to: PathBuf, write_through: bool },
    /// A file, link or empty directory was removed.
    Remove { path: PathBuf },
    /// The entries of a directory were synced (Unix).
    FlushDir { dir: PathBuf },
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TRACE: std::cell::RefCell<Vec<Event>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn emit(event: impl FnOnce() -> Event) {
    if !super::is_quiet() {
        TRACE.with(|trace| trace.borrow_mut().push(event()));
    }
}

#[cfg(not(any(test, feature = "test-support")))]
pub(super) fn emit(_event: impl FnOnce() -> Event) {}

/// Takes and clears this thread's trace.
#[cfg(any(test, feature = "test-support"))]
pub fn take() -> Vec<Event> {
    TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()))
}
