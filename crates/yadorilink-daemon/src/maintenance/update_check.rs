//! `UpdateCheckJob` -- one attempt of the periodic background update
//! check. See `maintenance_coordinator.rs`'s own spawn site for the full
//! jitter/backoff/`#[cfg]`-gating context this job's loop participates
//! in: this struct only owns the "one check" logic itself, not the
//! interval/backoff bookkeeping. `consecutive_failures` spans multiple
//! calls to `run_once` (it decides how long to sleep *between* calls),
//! so it stays loop state in the coordinator rather than moving into
//! this job -- narrowing this job down to `Arc<UpdateManager>` alone
//! would not be possible if it also owned that counter.

use std::sync::Arc;

use crate::update::manager::{UpdateError, UpdateManager};
use crate::update::manifest::Applicability;

pub(crate) struct UpdateCheckJob {
    update_manager: Arc<UpdateManager>,
}

impl UpdateCheckJob {
    pub(crate) fn new(update_manager: Arc<UpdateManager>) -> Self {
        Self { update_manager }
    }

    /// Runs one update-check attempt, honoring `automatic_checks_enabled`
    /// -- a disabled policy just means this call is a no-op (`None`), not
    /// that the caller's own loop stops running: `yadorilink update
    /// check` must still work regardless of whether the periodic check is
    /// enabled. Returns `None` when the check was skipped by policy,
    /// `Some(_)` with the check's own outcome otherwise -- the caller
    /// turns `Some(Err(_))` into the `consecutive_failures` backoff
    /// escalation and its own log line, since that bookkeeping spans
    /// multiple `run_once` calls and so isn't this job's own state.
    pub(crate) async fn run_once(&self) -> Option<Result<Applicability, UpdateError>> {
        let checks_enabled = self.update_manager.policy.load_or_default().automatic_checks_enabled;
        if !checks_enabled {
            return None;
        }
        Some(self.update_manager.check_now().await)
    }
}
