//! Fault injection at the transitions of a repair rebuild: a test arms one
//! [`RepairFailpoint`] on its own thread and the rebuild fails there, as if the step had
//! returned an error. In a production build every hook compiles to `Ok(())`.
//!
//! A test can also run an action at a transition instead of failing it ([`interleave`]): the
//! deterministic stand-in for something else touching the path at exactly that point.
//!
//! The repair runs synchronously on the caller's thread, so the armed set is per thread: tests
//! running in parallel never see each other's faults, whatever paths they use. The daemon's
//! write-operation matrix maps its own failpoint names onto these.

use crate::materialization_execution::MaterializationExecutionError;

/// A transition of a repair rebuild at which a test can inject a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepairFailpoint {
    /// The intent and fence are durable; no bytes are staged.
    AfterPrepare,
    /// The rebuilt bytes are in a temp file; the root was just proven.
    AfterStage,
    /// Nothing is renamed yet.
    BeforePublish,
    /// The bytes are under their name and the placement is recorded as landed; the metadata is
    /// not applied.
    AfterPublish,
    /// The sweep has read the row and the set of paths that carried an intent when the pass began,
    /// and has not yet looked at the intent or the proof for this decision. Not a transition of a
    /// rebuild, so it is not in [`Self::ALL`]; tests use it to change the path's state exactly
    /// between the pass's early snapshot and its fresh reads.
    AfterRowSnapshot,
}

impl RepairFailpoint {
    /// Every transition of a repair rebuild, in order.
    pub const ALL: [Self; 4] =
        [Self::AfterPrepare, Self::AfterStage, Self::BeforePublish, Self::AfterPublish];
}

/// Fails with an injected error when `point` is armed on this thread.
#[cfg(not(any(test, feature = "test-support")))]
#[inline(always)]
pub(crate) fn hit(_point: RepairFailpoint) -> Result<(), MaterializationExecutionError> {
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) use armed::hit;
#[cfg(any(test, feature = "test-support"))]
pub use armed::{arm, interleave, Armed, Interleaved};

#[cfg(any(test, feature = "test-support"))]
mod armed {
    use super::{MaterializationExecutionError, RepairFailpoint};
    use std::cell::RefCell;

    type Action = Box<dyn Fn()>;

    thread_local! {
        static ARMED: RefCell<Vec<(RepairFailpoint, usize)>> = const { RefCell::new(Vec::new()) };
        static INTERLEAVED: RefCell<Vec<(RepairFailpoint, Action)>> =
            const { RefCell::new(Vec::new()) };
    }

    /// Runs `action` on this thread each time the rebuild reaches `point`, until the guard is
    /// dropped; the rebuild then carries on.
    pub fn interleave(point: RepairFailpoint, action: impl Fn() + 'static) -> Interleaved {
        INTERLEAVED.with(|actions| actions.borrow_mut().push((point, Box::new(action))));
        Interleaved { point, _thread_bound: std::marker::PhantomData }
    }

    /// Bound to the arming thread, so it is not `Send`.
    pub struct Interleaved {
        point: RepairFailpoint,
        _thread_bound: std::marker::PhantomData<*const ()>,
    }

    impl Drop for Interleaved {
        fn drop(&mut self) {
            INTERLEAVED.with(|actions| actions.borrow_mut().retain(|(p, _)| *p != self.point));
        }
    }

    /// Arms `point` on this thread until the guard is dropped.
    pub fn arm(point: RepairFailpoint) -> Armed {
        ARMED.with(|armed| armed.borrow_mut().push((point, 0)));
        Armed { point, _thread_bound: std::marker::PhantomData }
    }

    /// Bound to the arming thread (the armed set is thread-local), so it is not `Send`.
    pub struct Armed {
        point: RepairFailpoint,
        _thread_bound: std::marker::PhantomData<*const ()>,
    }

    impl Armed {
        /// How many times the failpoint was hit.
        pub fn fired(&self) -> usize {
            ARMED.with(|armed| {
                armed.borrow().iter().find(|(p, _)| *p == self.point).map_or(0, |(_, n)| *n)
            })
        }

        /// The fault is cleared (the next pass runs without it).
        pub fn clear(&self) {
            ARMED.with(|armed| armed.borrow_mut().retain(|(p, _)| *p != self.point));
        }
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            self.clear();
        }
    }

    pub(crate) fn hit(point: RepairFailpoint) -> Result<(), MaterializationExecutionError> {
        INTERLEAVED.with(|actions| {
            for (at, action) in actions.borrow().iter() {
                if *at == point {
                    action();
                }
            }
        });
        ARMED.with(|armed| match armed.borrow_mut().iter_mut().find(|(p, _)| *p == point) {
            Some((_, fired)) => {
                *fired += 1;
                Err(MaterializationExecutionError::CorruptState(format!(
                    "injected failure at {point:?}"
                )))
            }
            None => Ok(()),
        })
    }
}
