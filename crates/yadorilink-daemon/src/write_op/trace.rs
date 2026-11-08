//! Records the ordered steps of the writes in a test, so a lane's order can be
//! checked against a golden trace. In a production build [`emit_at`] is empty.

use super::{StepEvent, WriteSpec};

/// Reports `event` of the write described by `spec`.
#[inline(always)]
pub fn emit(spec: &WriteSpec, event: StepEvent) {
    emit_at(&spec.group_id, &spec.path, event);
}

/// Reports `event` of the write at `path`, for a step that runs where the spec is no longer
/// in hand (the window's flush barrier).
#[cfg(not(any(test, feature = "test-support")))]
#[inline(always)]
pub fn emit_at(_group_id: &str, _path: &str, _event: StepEvent) {}

#[cfg(any(test, feature = "test-support"))]
pub use recorder::{emit_at, StepTrace};

#[cfg(any(test, feature = "test-support"))]
mod recorder {
    use super::StepEvent;
    use std::sync::Mutex;

    static EVENTS: Mutex<Vec<(String, String, StepEvent)>> = Mutex::new(Vec::new());

    pub fn emit_at(group_id: &str, path: &str, event: StepEvent) {
        EVENTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push((
            group_id.to_owned(),
            path.to_owned(),
            event,
        ));
    }

    /// The steps recorded for one path, in order.
    pub struct StepTrace;

    impl StepTrace {
        /// Steps recorded so far for `path` of `group_id`. Paths are unique
        /// per test, so tests running together do not see each other's.
        pub fn of(group_id: &str, path: &str) -> Vec<StepEvent> {
            EVENTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .filter(|(g, p, _)| g == group_id && p == path)
                .map(|(_, _, event)| *event)
                .collect()
        }
    }
}
