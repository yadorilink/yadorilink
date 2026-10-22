//! `PauseExpiryJob` -- resumes every link whose timed pause is over, through
//! the same resume a manual one uses. Runs once at startup and then on a
//! fixed tick; a pause therefore ends at most [`TICK`] after its deadline.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::pause_deadline::latest_plausible_deadline;

pub(crate) const TICK: Duration = Duration::from_secs(30);

pub(crate) struct PauseExpiryJob {
    controller: Arc<LinkRuntimeController>,
}

impl PauseExpiryJob {
    pub(crate) fn new(controller: Arc<LinkRuntimeController>) -> Self {
        Self { controller }
    }

    pub(crate) async fn run_once(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        self.run_once_at(now).await;
    }

    /// One pass at the wall-clock time `now_unix`.
    pub(crate) async fn run_once_at(&self, now_unix: i64) {
        let due =
            match self.controller.timed_pauses_due(now_unix, latest_plausible_deadline(now_unix)) {
                Ok(due) => due,
                Err(error) => {
                    tracing::warn!(%error, "could not read timed pauses");
                    return;
                }
            };
        for local_path in due {
            // A failure leaves the link paused and is tried again next tick.
            if let Err(error) = self.controller.resume(&local_path).await {
                tracing::warn!(%error, local_path, "could not end a timed pause");
            }
        }
    }
}

#[cfg(test)]
mod tests;
