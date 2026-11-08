//! The `reporting` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

/// Dispatch into `reporting_ipc`, which owns the actual
/// translation to/from `yadorilink_reporting`/`crate::reporting`
/// types.
pub(super) async fn reporting_status(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    RespPayload::ReportingStatus(encode_reporting_status(context.queries.reporting.status()))
}

pub(super) async fn generate_usage_report(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    RespPayload::GenerateUsageReport(reporting_ipc::generate_usage_report(
        &*context.application.reporting,
    ))
}

pub(super) async fn generate_last_error_report(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::GenerateLastErrorReportRequest,
) -> RespPayload {
    match reporting_ipc::generate_last_error_report(&*context.application.reporting, r.report_id) {
        Ok(resp) => RespPayload::GenerateLastErrorReport(resp),
        Err(e) => RespPayload::Error(e),
    }
}

pub(super) async fn list_queue_items(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    match context.queries.reporting.list_queue_items() {
        Ok(items) => RespPayload::ListQueueItems(ListQueueItemsResponse {
            items: items.into_iter().map(encode_queue_item).collect(),
        }),
        Err(e) => RespPayload::Error(e),
    }
}

pub(super) async fn show_queue_item(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ShowQueueItemRequest,
) -> RespPayload {
    match context.queries.reporting.show_queue_item(&r.report_id) {
        Ok(Some(report_json)) => RespPayload::ShowQueueItem(ShowQueueItemResponse { report_json }),
        Ok(None) => RespPayload::Error(format!("no queued report found with id `{}`", r.report_id)),
        Err(e) => RespPayload::Error(e),
    }
}

pub(super) async fn delete_queue_item(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::DeleteQueueItemRequest,
) -> RespPayload {
    match reporting_ipc::delete_queue_item(&*context.application.reporting, &r.report_id) {
        Ok(resp) => RespPayload::DeleteQueueItem(resp),
        Err(e) => RespPayload::Error(e),
    }
}

pub(super) async fn flush_queue(context: &crate::control_context::ControlContext) -> RespPayload {
    match reporting_ipc::flush_queue(&*context.application.reporting) {
        Ok(resp) => RespPayload::FlushQueue(resp),
        Err(e) => RespPayload::Error(e),
    }
}

pub(super) async fn submit_report(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::SubmitReportRequest,
) -> RespPayload {
    match reporting_ipc::submit_report(&*context.application.reporting, &r.report_json).await {
        Ok(resp) => RespPayload::SubmitReport(resp),
        Err(e @ SubmitReportError::NotEnabled) => {
            refused(&e.to_string(), NextStep::EnableReportSubmission)
        }
        Err(e @ SubmitReportError::Failed(_)) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn update_consent(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::UpdateConsentRequest,
) -> RespPayload {
    match reporting_ipc::update_consent(&*context.application.reporting, r) {
        Ok(resp) => RespPayload::UpdateConsent(resp),
        Err(e) => RespPayload::Error(e),
    }
}

/// Dispatch into `diagnostics_ipc`, which owns the actual bundle
/// assembly (from existing status/config/update/recent-error
/// sources) and the bounded-time-budget handling -- mirrors
/// `reporting_ipc`/`update_ipc`'s own dispatch pattern above.
/// Preview and Export both request the exact same daemon-side
/// bundle; only the CLI-side disposition of the result differs.
pub(super) async fn diagnostics_preview(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    RespPayload::DiagnosticsPreview(
        crate::diagnostics_ipc::build_bundle(&context.queries.diagnostics_bundle).await,
    )
}

pub(super) async fn diagnostics_export(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    RespPayload::DiagnosticsExport(
        crate::diagnostics_ipc::build_bundle(&context.queries.diagnostics_bundle).await,
    )
}

/// Dispatch into `connection_trace`.
pub(super) async fn list_connection_traces(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ListConnectionTracesRequest,
) -> RespPayload {
    let peer_device_id = (!r.peer_device_id.is_empty()).then_some(r.peer_device_id.as_str());
    let traces = context
        .queries
        .diagnostics
        .recent_connection_traces(peer_device_id)
        .into_iter()
        .map(|trace| ConnectionAttemptTrace {
            peer_device_id: trace.peer_device_id,
            candidate_source: trace.candidate_source.to_string(),
            address_class: trace.address_class.to_string(),
            outcome: trace.outcome.to_string(),
            latency_ms: trace.latency_ms,
            failure_category: trace.failure_category,
            selected: trace.selected,
            authorization_decision: trace.authorization_decision.to_string(),
            recorded_at_unix_nanos: trace.recorded_at_unix_nanos,
        })
        .collect();
    RespPayload::ListConnectionTraces(ListConnectionTracesResponse { traces })
}

pub(super) async fn connectivity_doctor(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    let categories = context
        .queries
        .diagnostics
        .connectivity_doctor()
        .into_iter()
        .map(|c| ConnectivityDoctorCategory {
            name: c.name.to_string(),
            status: c.status.to_string(),
            detail: c.detail,
        })
        .collect();
    RespPayload::ConnectivityDoctor(ConnectivityDoctorResponse { categories })
}
