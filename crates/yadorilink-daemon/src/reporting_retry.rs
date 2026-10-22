//! Daemon-side queue retry. Periodically attempts to submit every report
//! still sitting in the local queue (`QueueStore`), guarded by consent
//! state, endpoint availability, and `SubmissionClient`'s own rate limit —
//! this module never makes a network decision on its own that bypasses
//! those checks; it reuses `ConsentStore`/`SubmissionClient` rather than
//! adding a second consent-check path.
//!
//! Split out of the `reporting` module tree (rather than living at
//! `reporting::retry`) because this sweep needs `DaemonState` for its
//! background-task lifetime while the rest of `reporting` -- consent,
//! counters, and the queue itself -- does not; keeping them apart means a
//! reader of the queue (`RuntimeStatusQueryService`) never pulls in this
//! module's `DaemonState` coupling.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_reporting::schema::ReportType;
use yadorilink_reporting::submission::SubmissionClient;

use crate::daemon_state::DaemonState;

/// How often the background sweep runs. Reports aren't time-sensitive —
/// submission is explicit/asynchronous and must never block sync — so a
/// coarse interval is fine. This is a background safety net for "the
/// user opted into retry and the endpoint was temporarily down," not a
/// hot path.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// A queued entry stops being retried automatically after this many
/// failed attempts — left permanently queued (visible via `yadorilink
/// report queue list/show`) for the user to inspect/export/delete
/// manually, rather than retried forever.
pub const MAX_AUTOMATIC_RETRY_ATTEMPTS: u32 = 5;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetrySweepOutcome {
    pub attempted: u32,
    pub submitted: u32,
    pub gave_up: u32,
    /// Set when the sweep made zero network-relevant decisions because
    /// consent/endpoint gating stopped it before even listing the queue —
    /// distinct from "listed the queue and found nothing eligible."
    pub skipped_by_consent_gate: bool,
}

/// Runs one retry sweep and returns immediately — callers that want a
/// recurring background sweep should call this in a loop (see
/// `spawn_periodic`); exposed standalone so tests can call it directly
/// without waiting on `SWEEP_INTERVAL`.
///
/// Consent is re-checked here, not cached from anywhere else: guarded by
/// consent state, `queue_retry_enabled` must be on and an endpoint
/// (`consent.endpoint_override`) must be configured, or this returns
/// immediately having made zero calls into `client` — no `client.submit`
/// call is reachable from this function unless both are true, which is
/// what the "no network submission when consent is disabled" test below
/// exercises.
pub async fn run_retry_sweep_once(
    state: &DaemonState,
    client: &SubmissionClient,
) -> RetrySweepOutcome {
    let consent = state.reporting.consent_or_default();
    if !consent.queue_retry_enabled || consent.endpoint_override.is_none() {
        return RetrySweepOutcome { skipped_by_consent_gate: true, ..Default::default() };
    }

    let mut outcome = RetrySweepOutcome::default();
    let entries = match state.reporting.queue().list() {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(error = %e, "reporting: queue retry sweep failed to list queue");
            return outcome;
        }
    };

    for entry in entries {
        if entry.submit_attempts >= MAX_AUTOMATIC_RETRY_ATTEMPTS {
            continue;
        }
        // A per-report-type consent check on top of `queue_retry_enabled`
        // above: opting into retrying already-queued *usage* reports
        // doesn't imply consent to auto-submit *error* reports, and vice
        // versa — automatic error submission requires explicit opt-in
        // separate from usage-summary opt-in.
        let allowed = match entry.report_type {
            ReportType::Usage => consent.usage_submission_enabled,
            ReportType::Error => consent.error_submission_enabled,
        };
        if !allowed {
            continue;
        }
        let Ok(Some(envelope)) = state.reporting.queue().show(&entry.report_id) else { continue };
        outcome.attempted += 1;
        match client.submit(&entry.report_id, &envelope, consent.endpoint_override.as_deref()).await
        {
            Ok(_receipt) => {
                let _ = state.reporting.queue().delete(&entry.report_id);
                outcome.submitted += 1;
            }
            Err(e) => {
                tracing::debug!(error = %e, report_id = %entry.report_id, "reporting: queued submission attempt failed");
                // Retryable or not, record the attempt: a permanent
                // failure (e.g. invalid payload) will fail identically on
                // every future sweep, so there is nothing to gain from
                // distinguishing it here — both paths converge on "stop
                // after MAX_AUTOMATIC_RETRY_ATTEMPTS."
                if let Ok(Some(new_count)) =
                    state.reporting.queue().increment_submit_attempts(&entry.report_id)
                {
                    if new_count >= MAX_AUTOMATIC_RETRY_ATTEMPTS || !e.is_retryable() {
                        outcome.gave_up += 1;
                    }
                }
            }
        }
    }
    outcome
}

/// `ReportingRetryJob` -- a thin wrapper around
/// [`run_retry_sweep_once`] above, giving this daemon-wide maintenance
/// sweep the same named-job-with-`run_once` shape as this crate's other
/// periodic tasks (see `maintenance/mod.rs`'s own doc) without
/// duplicating this module's own logic, which was already almost exactly
/// that shape. Interval-only -- no startup-immediate run, unchanged from
/// before this reorganization.
pub(crate) struct ReportingRetryJob {
    state: Arc<DaemonState>,
    client: SubmissionClient,
}

impl ReportingRetryJob {
    pub(crate) fn new(state: Arc<DaemonState>, client: SubmissionClient) -> Self {
        Self { state, client }
    }

    pub(crate) async fn run_once(&self) -> RetrySweepOutcome {
        run_retry_sweep_once(&self.state, &self.client).await
    }
}

/// Spawns the recurring background sweep as a supervised task — logged,
/// not restarted, since a panic here would indicate a real bug, not a
/// transient condition worth restarting into.
pub fn spawn_periodic(state: Arc<DaemonState>) {
    crate::supervise::spawn_logged("reporting-queue-retry", async move {
        let Ok(client) = SubmissionClient::with_default_config() else {
            tracing::warn!(
                "reporting: failed to construct submission client; queue retry disabled for this process"
            );
            return Ok(());
        };
        let job = ReportingRetryJob::new(state, client);
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            job.run_once().await;
        }
    });
}

#[cfg(test)]
mod tests;
