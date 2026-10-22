//! `ReportingStorage`-backed [`ReportingCommandPort`]. Holds `Arc<
//! ReportingStorage>` directly (no `Arc<DaemonState>` strangler) --
//! matches `ReportingQueryService`'s own read-side adapter shape, since
//! every one of these operations only ever touched `state.reporting`.

use std::sync::Arc;

use yadorilink_reporting::consent::ConsentState;
use yadorilink_reporting::local_store::environment;
use yadorilink_reporting::schema::{ReportEnvelope, ReportType};
use yadorilink_reporting::submission::SubmissionClient;

use crate::application::ports::{
    BoxFuture, ConsentCommand, LastErrorReport, ReportingCommandPort,
    ReportingRedactionCategoryCount, SubmitReportOutcome,
};
use crate::reporting::ReportingStorage;

pub(crate) struct DaemonReportingCommandAdapter {
    reporting: Arc<ReportingStorage>,
}

impl DaemonReportingCommandAdapter {
    pub(crate) fn new(reporting: Arc<ReportingStorage>) -> Self {
        Self { reporting }
    }
}

impl ReportingCommandPort for DaemonReportingCommandAdapter {
    fn generate_usage_report(&self) -> String {
        let consent = self.reporting.consent_or_default();
        let env = environment::current(&consent);
        let payload = self.reporting.counters().to_usage_payload();
        yadorilink_reporting::builder::build_usage_envelope(env, payload).to_json()
    }

    fn generate_last_error_report(
        &self,
        report_id: Option<String>,
    ) -> Result<LastErrorReport, String> {
        let candidates = self.reporting.error_candidates();
        let id = match report_id {
            Some(id) => id,
            None => match candidates.most_recent().map_err(|e| e.to_string())? {
                Some(meta) => meta.report_id,
                None => return Err("no error candidate is available yet".to_string()),
            },
        };
        let Some((envelope, summary)) =
            candidates.show_with_summary(&id).map_err(|e| e.to_string())?
        else {
            return Err(format!("no error candidate found with id `{id}`"));
        };
        let redaction_summary = summary
            .categories
            .iter()
            .map(|(category, count)| ReportingRedactionCategoryCount {
                category: format!("{category:?}"),
                count: *count as u32,
            })
            .collect();
        Ok(LastErrorReport { report_id: id, report_json: envelope.to_json(), redaction_summary })
    }

    fn delete_queue_item(&self, report_id: &str) -> Result<bool, String> {
        self.reporting.queue().delete(report_id).map_err(|e| e.to_string())
    }

    fn flush_queue(&self) -> Result<u32, String> {
        self.reporting.queue().flush().map_err(|e| e.to_string()).map(|removed| removed as u32)
    }

    fn submit_report<'a>(
        &'a self,
        report_json: &'a str,
    ) -> BoxFuture<'a, Result<SubmitReportOutcome, String>> {
        Box::pin(async move {
            let envelope = ReportEnvelope::from_json(report_json).map_err(|e| e.to_string())?;
            envelope.validate().map_err(|e| e.to_string())?;

            let consent = self.reporting.consent_or_default();
            let allowed = match envelope.report_type {
                ReportType::Usage => consent.usage_submission_enabled,
                ReportType::Error => consent.error_submission_enabled,
            };
            if !allowed {
                return Err(
                    "submission is not enabled for this report type — run `yadorilink report consent enable-usage` or `enable-error` first, or use --export instead"
                        .to_string(),
                );
            }

            let report_id = uuid::Uuid::new_v4().to_string();
            let client = SubmissionClient::with_default_config().map_err(|e| e.to_string())?;
            match client.submit(&report_id, &envelope, consent.endpoint_override.as_deref()).await {
                Ok(receipt) => Ok(SubmitReportOutcome {
                    receipt_id: receipt.receipt_id,
                    submitted_at: receipt.submitted_at,
                    queued_for_retry: false,
                }),
                Err(e) if consent.queue_retry_enabled && e.is_retryable() => {
                    self.reporting.queue().enqueue(envelope).map_err(|e| e.to_string())?;
                    Ok(SubmitReportOutcome {
                        receipt_id: String::new(),
                        submitted_at: String::new(),
                        queued_for_retry: true,
                    })
                }
                Err(e) => Err(e.to_string()),
            }
        })
    }

    fn update_consent(&self, command: ConsentCommand) -> Result<ConsentState, String> {
        let consent_store = self.reporting.consent();
        match command {
            ConsentCommand::EnableUsage => consent_store.opt_in_usage(),
            ConsentCommand::EnableError => consent_store.opt_in_error_reporting(),
            ConsentCommand::EnableCrashReporting => consent_store.opt_in_crash_reporting(),
            ConsentCommand::DisableAll => consent_store.disable_all_submission(),
            ConsentCommand::ResetId => consent_store.reset_reporter_id(),
            ConsentCommand::SetPrompt(enabled) => {
                consent_store.set_prompt_to_report_enabled(enabled)
            }
            ConsentCommand::SetQueueRetry(enabled) => {
                consent_store.set_queue_retry_enabled(enabled)
            }
            ConsentCommand::SetEndpoint(endpoint) => consent_store.set_endpoint_override(endpoint),
        }
        .map_err(|e| e.to_string())
    }
}
