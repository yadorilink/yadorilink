//! A record of what the repair sweep did with each row, for the tests that pin it.
//!
//! The sweep names the action of a row with `verdict` and carries it out; this records, per row,
//! the kind of object, the state the facts placed it in, the action actually taken and the verdict,
//! so a test that runs the real sweep can read which `(kind, state, action, verdict)` cells it
//! reached (`materialization_execution/tests/link_dir_cells.rs` pins them). Nothing is recorded
//! outside a test build.

use std::cell::Cell;

use yadorilink_replica_domain::crash_state::{classify, CrashFacts, RecoveryAction};

/// Carries the facts, the verdict and the action taken for the row being repaired out of the
/// per-path code.
#[derive(Debug)]
pub(crate) struct RowTrace {
    facts: Cell<Option<CrashFacts>>,
    verdict: Cell<RecoveryAction>,
    taken: Cell<RecoveryAction>,
    /// What the row being repaired is: `file`, `symlink` or `directory`.
    kind: Cell<&'static str>,
}

impl RowTrace {
    pub(crate) fn new() -> Self {
        Self {
            facts: Cell::new(None),
            verdict: Cell::new(RecoveryAction::Leave),
            taken: Cell::new(RecoveryAction::Leave),
            kind: Cell::new("file"),
        }
    }

    pub(crate) fn begin_row(&self) {
        self.facts.set(None);
        self.verdict.set(RecoveryAction::Leave);
        self.taken.set(RecoveryAction::Leave);
        self.kind.set("file");
    }

    /// The row is not a regular file.
    pub(crate) fn set_kind(&self, kind: &'static str) {
        self.kind.set(kind);
    }

    /// The facts the row was placed by and the verdict they gave.
    pub(crate) fn set_row(&self, facts: CrashFacts, verdict: RecoveryAction) {
        self.facts.set(Some(facts));
        self.verdict.set(verdict);
    }

    /// Records the first action that changes anything for this row: a quarantine that is followed
    /// by a rebuild is a quarantine.
    pub(crate) fn act(&self, action: RecoveryAction) {
        if self.taken.get() == RecoveryAction::Leave {
            self.taken.set(action);
        }
    }

    /// The row just repaired is done. A row that was never classified (no facts) records nothing.
    ///
    /// In a test build it also holds every sweep to its verdict: the action taken is `Leave` (the
    /// path was handed on), the verdict, or the fallback to demotion after a rebuild that was
    /// chosen and failed. Anything else is a sweep that decided for itself.
    pub(crate) fn finish_row(&self) {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(facts) = self.facts.get() {
            let (taken, verdict) = (self.taken.get(), self.verdict.get());
            assert!(
                taken == RecoveryAction::Leave
                    || taken == verdict
                    || (taken == RecoveryAction::Demote
                        && matches!(verdict, RecoveryAction::Rebuild | RecoveryAction::Quarantine)),
                "the repair sweep took {taken:?} where the crash-state table says {verdict:?}: {facts:?}"
            );
            cells::push(
                self.kind.get(),
                format!("{:?}", classify(&facts)),
                format!("{:?}", self.taken.get()),
                format!("{:?}", self.verdict.get()),
            );
        }
        #[cfg(not(any(test, feature = "test-support")))]
        let _ = classify;
    }
}

#[cfg(any(test, feature = "test-support"))]
mod cells {
    thread_local! {
        static CELLS: std::cell::RefCell<Vec<(String, String, String, String)>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    pub(super) fn push(kind: &str, state: String, taken: String, verdict: String) {
        CELLS.with(|cells| cells.borrow_mut().push((kind.to_string(), state, taken, verdict)));
    }

    pub(super) fn take() -> Vec<(String, String, String, String)> {
        CELLS.with(|cells| std::mem::take(&mut *cells.borrow_mut()))
    }
}

/// The `(kind, state, action, verdict)` of every row classified by sweeps that ran on this thread
/// since the last call, so a test that runs the sweep itself can read which cells it reached.
#[cfg(any(test, feature = "test-support"))]
pub fn take_thread_cells() -> Vec<(String, String, String, String)> {
    cells::take()
}
