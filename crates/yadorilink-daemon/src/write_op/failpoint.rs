//! Fault injection at the transitions of a write: a test arms one
//! [`WriteOpFailpoint`] for one path and the write fails there, as if the
//! step had returned an I/O error. In a production build every hook compiles
//! to `Ok(())`.

use yadorilink_peer_session::PeerSessionError;

/// A transition of a write at which a test can inject a failure. Each hook
/// sits next to the [`super::StepEvent`] it follows or precedes.
///
/// `AfterPublish` and `AfterProve` fail a step that cannot fail in production: the error
/// replaces an outcome that is already durable (in a deferred run the completion window still
/// holds the file's flush entry). `AfterBarrier2` is a probe that only counts hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WriteOpFailpoint {
    /// Transaction one is committed; nothing is staged.
    AfterPrepare,
    /// The temp file is staged and flushed as far as its class requires.
    AfterStage,
    /// The pre-publish checks passed; the rename has not run.
    BeforePublish,
    /// The bytes are under their name.
    AfterPublish,
    /// The metadata is applied and the object is verified on disk.
    AfterObserve,
    /// Nothing of the proof is committed yet.
    BeforeProve,
    /// The proof transaction committed.
    AfterProve,
    /// The window's flush barrier made the names durable; the intents are not cleared.
    BeforeBarrier2,
    /// The barrier cleared the intents of the flushed files.
    AfterBarrier2,
}

impl WriteOpFailpoint {
    /// Every variant, in transition order.
    pub const ALL: [Self; 9] = [
        Self::AfterPrepare,
        Self::AfterStage,
        Self::BeforePublish,
        Self::AfterPublish,
        Self::AfterObserve,
        Self::BeforeProve,
        Self::AfterProve,
        Self::BeforeBarrier2,
        Self::AfterBarrier2,
    ];
}

/// Fails with an injected I/O error when `point` is armed for `path`.
#[cfg(not(any(test, feature = "test-support")))]
#[inline(always)]
pub fn hit(_point: WriteOpFailpoint, _path: &str) -> Result<(), PeerSessionError> {
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub use armed::{arm, hit, Armed};

#[cfg(any(test, feature = "test-support"))]
mod armed {
    use super::{PeerSessionError, WriteOpFailpoint};
    use std::sync::Mutex;

    struct Entry {
        point: WriteOpFailpoint,
        path: String,
        fired: usize,
        id: u64,
    }

    static ARMED: Mutex<(u64, Vec<Entry>)> = Mutex::new((0, Vec::new()));

    fn lock() -> std::sync::MutexGuard<'static, (u64, Vec<Entry>)> {
        ARMED.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Arms `point` for `path` until the returned guard is dropped. Paths are unique per test,
    /// so tests running together do not trip each other's failpoints.
    pub fn arm(point: WriteOpFailpoint, path: &str) -> Armed {
        let mut state = lock();
        state.0 += 1;
        let id = state.0;
        state.1.push(Entry { point, path: path.to_owned(), fired: 0, id });
        Armed { id }
    }

    pub struct Armed {
        id: u64,
    }

    impl Armed {
        /// How many times the failpoint was hit.
        pub fn fired(&self) -> usize {
            lock().1.iter().find(|e| e.id == self.id).map_or(0, |e| e.fired)
        }

        /// The fault is cleared (the retry runs without it).
        pub fn clear(&self) {
            lock().1.retain(|e| e.id != self.id);
        }
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            self.clear();
        }
    }

    pub fn hit(point: WriteOpFailpoint, path: &str) -> Result<(), PeerSessionError> {
        let mut state = lock();
        match state.1.iter_mut().find(|e| e.point == point && e.path == path) {
            Some(entry) => {
                entry.fired += 1;
                Err(PeerSessionError::Io(std::io::Error::other(format!(
                    "injected failure at {point:?}"
                ))))
            }
            None => Ok(()),
        }
    }
}
