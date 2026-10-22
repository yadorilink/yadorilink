//! bounded local storage for reports the user has already confirmed (a
//! usage summary or an error report) but that haven't been submitted yet —
//! either because network submission is disabled, the submission attempt
//! failed, or the user asked to export/inspect later instead. `flush` here
//! means "delete every queued entry": actually retrying submission against
//! a configured endpoint is section 3.5/5's job (the daemon-side retry
//! loop and the HTTPS submission client, neither of which exists yet);
//! this storage layer only owns the bounded on-disk list, not the
//! transport.

use std::path::PathBuf;

use yadorilink_reporting::local_store::entry_store::EntryStore;
use yadorilink_reporting::local_store::error::ReportingResult;
use yadorilink_reporting::queue::{QueuedReportMetadata, RetentionPolicy};
use yadorilink_reporting::schema::ReportEnvelope;

pub struct QueueStore {
    inner: EntryStore,
}

impl QueueStore {
    pub fn new(reporting_dir: impl Into<PathBuf>) -> Self {
        QueueStore::with_policy(reporting_dir, RetentionPolicy::default())
    }

    pub fn with_policy(reporting_dir: impl Into<PathBuf>, policy: RetentionPolicy) -> Self {
        QueueStore { inner: EntryStore::new(reporting_dir.into().join("queue"), policy) }
    }

    pub fn enqueue(&self, envelope: ReportEnvelope) -> ReportingResult<QueuedReportMetadata> {
        self.inner.insert(envelope)
    }

    pub fn list(&self) -> ReportingResult<Vec<QueuedReportMetadata>> {
        self.inner.list()
    }

    pub fn show(&self, report_id: &str) -> ReportingResult<Option<ReportEnvelope>> {
        self.inner.show(report_id)
    }

    pub fn delete(&self, report_id: &str) -> ReportingResult<bool> {
        self.inner.delete(report_id)
    }

    /// bumps `report_id`'s `submit_attempts` after a failed,
    /// retryable submission attempt — used by the queue-retry sweep's
    /// backoff (`retry.rs`) to eventually give up on an entry that keeps
    /// failing rather than retrying it forever.
    pub fn increment_submit_attempts(&self, report_id: &str) -> ReportingResult<Option<u32>> {
        self.inner.increment_submit_attempts(report_id)
    }

    /// Deletes every queued report. See module doc comment for why this
    /// doesn't attempt a submit-then-clear cycle.
    pub fn flush(&self) -> ReportingResult<usize> {
        self.inner.flush()
    }

    pub fn apply_retention(&self) -> ReportingResult<Vec<String>> {
        self.inner.apply_retention()
    }
}

#[cfg(test)]
mod tests;
