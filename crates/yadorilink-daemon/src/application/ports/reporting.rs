//! Write-side of the reporting IPC surface -- generate/queue/submit/
//! consent commands. The read-only trio (`ReportingStatus`/
//! `ListQueueItems`/`ShowQueueItem`) already lives under the read-model
//! query layer's own reporting module; this port is strictly the
//! mutating half.

use yadorilink_reporting::consent::ConsentState;

/// Application-owned mirror of the proto `ConsentAction` enum -- kept
/// distinct so `application` never names an IPC-proto type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConsentCommand {
    EnableUsage,
    EnableError,
    EnableCrashReporting,
    DisableAll,
    ResetId,
    SetPrompt(bool),
    SetQueueRetry(bool),
    SetEndpoint(Option<String>),
}

#[derive(Debug, Clone)]
pub(crate) struct RedactionCategoryCount {
    pub(crate) category: String,
    pub(crate) count: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct LastErrorReport {
    pub(crate) report_id: String,
    pub(crate) report_json: String,
    pub(crate) redaction_summary: Vec<RedactionCategoryCount>,
}

#[derive(Debug, Clone)]
pub(crate) struct SubmitReportOutcome {
    pub(crate) receipt_id: String,
    pub(crate) submitted_at: String,
    pub(crate) queued_for_retry: bool,
}

pub(crate) trait ReportingCommandPort: Send + Sync {
    /// Never fails: builds a usage envelope straight from in-memory
    /// counters, no I/O beyond what's already been loaded.
    fn generate_usage_report(&self) -> String;

    /// `report_id: None` resolves to the most recent error candidate.
    fn generate_last_error_report(
        &self,
        report_id: Option<String>,
    ) -> Result<LastErrorReport, String>;

    fn delete_queue_item(&self, report_id: &str) -> Result<bool, String>;

    fn flush_queue(&self) -> Result<u32, String>;

    fn submit_report<'a>(
        &'a self,
        report_json: &'a str,
    ) -> super::common::BoxFuture<'a, Result<SubmitReportOutcome, String>>;

    fn update_consent(&self, command: ConsentCommand) -> Result<ConsentState, String>;
}
