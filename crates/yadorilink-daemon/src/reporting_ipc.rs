//! IPC encode/decode for the reporting write surface added to
//! `daemon_control.proto` -- protobuf request -> application command,
//! and application outcome -> protobuf response. All actual reporting
//! logic lives behind `ReportingCommandPort`
//! (`crate::application::ports::reporting`); this module never touches
//! `ReportingStorage`/`SubmissionClient` directly.
//!
//! The read-only trio (`ReportingStatus`/`ListQueueItems`/`ShowQueueItem`)
//! is handled entirely in `control_socket.rs` via `context.queries.
//! reporting` + its own `encode_reporting_status`/`encode_queue_item` --
//! this module is the write side's counterpart.

use yadorilink_ipc_proto::daemonctl::{
    ConsentAction, DeleteQueueItemResponse, FlushQueueResponse, GenerateLastErrorReportResponse,
    GenerateUsageReportResponse, RedactionCategoryCount, ReportingConsentState,
    SubmitReportResponse, UpdateConsentRequest, UpdateConsentResponse,
};
use yadorilink_reporting::consent::ConsentState;

use crate::application::ports::ReportingCommandPort;
use crate::application::{ConsentCommand, LastErrorReport};

pub(crate) fn generate_usage_report(
    port: &dyn ReportingCommandPort,
) -> GenerateUsageReportResponse {
    GenerateUsageReportResponse { report_json: port.generate_usage_report() }
}

pub(crate) fn generate_last_error_report(
    port: &dyn ReportingCommandPort,
    report_id: Option<String>,
) -> Result<GenerateLastErrorReportResponse, String> {
    port.generate_last_error_report(report_id).map(encode_last_error_report)
}

fn encode_last_error_report(report: LastErrorReport) -> GenerateLastErrorReportResponse {
    GenerateLastErrorReportResponse {
        report_id: report.report_id,
        report_json: report.report_json,
        redaction_summary: report
            .redaction_summary
            .into_iter()
            .map(|c| RedactionCategoryCount { category: c.category, count: c.count })
            .collect(),
    }
}

pub(crate) fn delete_queue_item(
    port: &dyn ReportingCommandPort,
    report_id: &str,
) -> Result<DeleteQueueItemResponse, String> {
    port.delete_queue_item(report_id).map(|deleted| DeleteQueueItemResponse { deleted })
}

pub(crate) fn flush_queue(port: &dyn ReportingCommandPort) -> Result<FlushQueueResponse, String> {
    port.flush_queue().map(|removed_count| FlushQueueResponse { removed_count })
}

pub(crate) async fn submit_report(
    port: &dyn ReportingCommandPort,
    report_json: &str,
) -> Result<SubmitReportResponse, String> {
    port.submit_report(report_json).await.map(|outcome| SubmitReportResponse {
        receipt_id: outcome.receipt_id,
        submitted_at: outcome.submitted_at,
        queued_for_retry: outcome.queued_for_retry,
    })
}

pub(crate) fn update_consent(
    port: &dyn ReportingCommandPort,
    req: UpdateConsentRequest,
) -> Result<UpdateConsentResponse, String> {
    let command = match ConsentAction::try_from(req.action) {
        Ok(ConsentAction::EnableUsage) => ConsentCommand::EnableUsage,
        Ok(ConsentAction::EnableError) => ConsentCommand::EnableError,
        Ok(ConsentAction::EnableCrashReporting) => ConsentCommand::EnableCrashReporting,
        Ok(ConsentAction::DisableAll) => ConsentCommand::DisableAll,
        Ok(ConsentAction::ResetId) => ConsentCommand::ResetId,
        Ok(ConsentAction::SetPrompt) => ConsentCommand::SetPrompt(req.bool_value.unwrap_or(false)),
        Ok(ConsentAction::SetQueueRetry) => {
            ConsentCommand::SetQueueRetry(req.bool_value.unwrap_or(false))
        }
        Ok(ConsentAction::SetEndpoint) => {
            ConsentCommand::SetEndpoint(req.string_value.filter(|s| !s.is_empty()))
        }
        Ok(ConsentAction::Unspecified) | Err(_) => {
            return Err("unspecified consent action".to_string())
        }
    };
    port.update_consent(command)
        .map(|consent| UpdateConsentResponse { consent: Some(consent_to_proto(&consent)) })
}

fn consent_to_proto(consent: &ConsentState) -> ReportingConsentState {
    ReportingConsentState {
        usage_submission_enabled: consent.usage_submission_enabled,
        error_submission_enabled: consent.error_submission_enabled,
        prompt_to_report_enabled: consent.prompt_to_report_enabled,
        queue_retry_enabled: consent.queue_retry_enabled,
        anonymous_reporter_id: consent.anonymous_reporter_id.clone(),
        endpoint_override: consent.endpoint_override.clone(),
    }
}
