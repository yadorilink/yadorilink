//! `DaemonState`-backed [`EnrollmentAttemptTracker`] -- the in-memory
//! (never persisted) transient-attempt counter.

use std::sync::Arc;

use crate::application::ports::EnrollmentAttemptTracker;
use crate::daemon_state::DaemonState;

pub(crate) struct DaemonEnrollmentAttemptTracker {
    state: Arc<DaemonState>,
}

impl DaemonEnrollmentAttemptTracker {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl EnrollmentAttemptTracker for DaemonEnrollmentAttemptTracker {
    fn note_transient_attempt(&self, operation_id: &str) -> u32 {
        self.state.note_pending_enrollment_transient_attempt(operation_id)
    }

    fn clear_transient_attempts(&self, operation_id: &str) {
        self.state.clear_pending_enrollment_transient_attempts(operation_id)
    }
}
