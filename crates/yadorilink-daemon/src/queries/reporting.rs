//! Read-only slice of the reporting IPC surface -- `ReportingStatus`/
//! `ListQueueItems`/`ShowQueueItem`. The write side (`GenerateUsageReport`/
//! `GenerateLastErrorReport`/`DeleteQueueItem`/`FlushQueue`/`SubmitReport`/
//! `UpdateConsent`) goes through `reporting_ipc.rs` and
//! `ReportingCommandPort`, not here.

use std::sync::Arc;

use yadorilink_reporting::consent::ConsentState;
use yadorilink_reporting::schema::ReportType;

use crate::reporting::ReportingStorage;

#[derive(Debug, Clone)]
pub(crate) struct ReportingStatusView {
    pub(crate) consent: ConsentState,
    pub(crate) queue_count: u32,
    pub(crate) error_candidate_count: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct QueueItemView {
    pub(crate) report_id: String,
    pub(crate) report_type: ReportType,
    pub(crate) queued_at: String,
    pub(crate) size_bytes: u64,
    pub(crate) submit_attempts: u32,
}

pub(crate) struct ReportingQueryService {
    reporting: Arc<ReportingStorage>,
}

impl ReportingQueryService {
    pub(crate) fn new(reporting: Arc<ReportingStorage>) -> Self {
        Self { reporting }
    }

    pub(crate) fn status(&self) -> ReportingStatusView {
        let consent = self.reporting.consent_or_default();
        let queue_count = self.reporting.queue().list().map(|v| v.len()).unwrap_or(0) as u32;
        let error_candidate_count =
            self.reporting.error_candidates().list().map(|v| v.len()).unwrap_or(0) as u32;
        ReportingStatusView { consent, queue_count, error_candidate_count }
    }

    pub(crate) fn list_queue_items(&self) -> Result<Vec<QueueItemView>, String> {
        Ok(self
            .reporting
            .queue()
            .list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|m| QueueItemView {
                report_id: m.report_id,
                report_type: m.report_type,
                queued_at: m.queued_at,
                size_bytes: m.size_bytes as u64,
                submit_attempts: m.submit_attempts,
            })
            .collect())
    }

    /// `Ok(None)` when no queued report matches `report_id` -- distinct
    /// from an error reading the queue store itself.
    pub(crate) fn show_queue_item(&self, report_id: &str) -> Result<Option<String>, String> {
        self.reporting
            .queue()
            .show(report_id)
            .map(|opt| opt.map(|envelope| envelope.to_json()))
            .map_err(|e| e.to_string())
    }
}
