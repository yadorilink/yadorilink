//! Consent state shape. This module defines the type only —
//! persistence (reading/writing it under the daemon's config directory)
//! is `yadorilink-daemon`'s job, which is the only place that should
//! ever construct or mutate one of these outside tests.

use serde::{Deserialize, Serialize};

/// Every field defaults to the least-sharing option. `ConsentState::default`
/// is the state a fresh install starts in: no network submission, no
/// automatic error submission, no anonymous reporter ID (one is created
/// only by `opt_in_usage`/`opt_in_error_reporting`, never implicitly).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsentState {
    pub usage_submission_enabled: bool,
    pub error_submission_enabled: bool,
    pub prompt_to_report_enabled: bool,
    pub queue_retry_enabled: bool,
    pub anonymous_reporter_id: Option<String>,
    pub endpoint_override: Option<String>,
}

impl Default for ConsentState {
    fn default() -> Self {
        ConsentState {
            usage_submission_enabled: false,
            error_submission_enabled: false,
            // Prompting (a purely local, no-network suggestion to run
            // `yadorilink report error --last`) defaults to on: it costs
            // the user nothing and is how they'd discover the feature
            // exists, unlike the two submission toggles above.
            prompt_to_report_enabled: true,
            queue_retry_enabled: false,
            anonymous_reporter_id: None,
            endpoint_override: None,
        }
    }
}

impl ConsentState {
    /// Enables usage-summary submission, creating an anonymous reporter
    /// ID if one doesn't already exist. Does not touch
    /// `error_submission_enabled` — usage and automatic-error submission
    /// are separate toggles.
    pub fn opt_in_usage(&mut self, new_reporter_id: impl FnOnce() -> String) {
        self.usage_submission_enabled = true;
        if self.anonymous_reporter_id.is_none() {
            self.anonymous_reporter_id = Some(new_reporter_id());
        }
    }

    pub fn opt_in_error_reporting(&mut self, new_reporter_id: impl FnOnce() -> String) {
        self.error_submission_enabled = true;
        if self.anonymous_reporter_id.is_none() {
            self.anonymous_reporter_id = Some(new_reporter_id());
        }
    }

    /// Enables automatic crash/error submission together with background
    /// queue retry, so a captured crash is submitted (or, if the network
    /// send fails, queued and later retried) without any further
    /// per-report action. Creates an anonymous reporter ID if one doesn't
    /// already exist.
    pub fn opt_in_crash_reporting(&mut self, new_reporter_id: impl FnOnce() -> String) {
        self.error_submission_enabled = true;
        self.queue_retry_enabled = true;
        if self.anonymous_reporter_id.is_none() {
            self.anonymous_reporter_id = Some(new_reporter_id());
        }
    }

    pub fn disable_all_submission(&mut self) {
        self.usage_submission_enabled = false;
        self.error_submission_enabled = false;
        self.queue_retry_enabled = false;
    }

    /// Resets the anonymous reporter ID without touching consent flags —
    /// a user who's opted in can still get a fresh ID (severing any
    /// correlation with reports already submitted under the old one)
    /// without having to opt out and back in.
    pub fn reset_reporter_id(&mut self, new_reporter_id: impl FnOnce() -> String) {
        self.anonymous_reporter_id = Some(new_reporter_id());
    }

    /// Reporting is entirely off in the sense that matters for "is it
    /// safe to skip prompting/queueing work at all": no submission
    /// paths are active. `prompt_to_report_enabled` doesn't factor in
    /// here since prompting alone sends nothing.
    pub fn is_fully_disabled(&self) -> bool {
        !self.usage_submission_enabled && !self.error_submission_enabled
    }
}

#[cfg(test)]
mod tests;
