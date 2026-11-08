//! The `daemon` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

pub(super) async fn status(context: &crate::control_context::ControlContext) -> RespPayload {
    match context.status_hub.status().await {
        Ok(response) => RespPayload::Status(response),
        Err(message) => RespPayload::Error(message),
    }
}

pub(super) async fn shutdown(
    context: &crate::control_context::ControlContext,
    request: yadorilink_ipc_proto::daemonctl::ShutdownRequest,
) -> RespPayload {
    tracing::info!("shutdown requested via control socket");
    // route through the same graceful-shutdown path
    // `main.rs` uses for SIGTERM/SIGINT instead of calling
    // `std::process::exit` directly here — that used to skip
    // aborting watcher tasks, draining in-flight broadcasts, and
    // removing socket files. `main.rs`'s top-level `select!` holds
    // the matching receiver and does the actual teardown/exit
    // once it observes this; a `send` error just means every
    // receiver (i.e. `main.rs` itself) is already gone, which
    // only happens if the process is already on its way out.
    if request.restart {
        context.application.lifecycle.request_shutdown_to_restart();
    } else {
        context.application.lifecycle.request_shutdown();
    }
    RespPayload::Shutdown(ShutdownResponse {})
}

pub(super) async fn request_safe_stop(
    context: &crate::control_context::ControlContext,
    request: yadorilink_ipc_proto::daemonctl::RequestSafeStopRequest,
) -> RespPayload {
    let outcome = context
        .application
        .lifecycle
        .request_safe_stop(crate::application::ports::safe_stop_deadline(request.deadline_secs))
        .await;
    RespPayload::RequestSafeStop(encode_safe_stop(outcome))
}

pub(super) async fn identify(context: &crate::control_context::ControlContext) -> RespPayload {
    RespPayload::Identify(context.identity.report())
}

pub(super) async fn health(context: &crate::control_context::ControlContext) -> RespPayload {
    RespPayload::Health(encode_health(context.queries.health.snapshot()))
}

/// Dispatch into `gc::run_sweep`, which owns the actual
/// mark-and-sweep, daemon-wide mutual-exclusion, and
/// never-mid-burst logic -- this arm only translates to/from the
/// wire types, mirroring
/// `reporting_ipc`/`update_ipc`/`diagnostics_ipc`'s own dispatch
/// pattern above. `GcTriggerError`'s `Display` (already a clear,
/// actionable message for `AlreadyRunning`/`SyncBurstInProgress`)
/// is surfaced directly as `DaemonControlResponse.error`, same as
/// every other fallible request in this match.
pub(super) async fn gc(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::GcRequest,
) -> RespPayload {
    match context.application.gc.run_sweep(r.dry_run).await {
        Ok(report) => {
            let usage = if r.dry_run {
                context.queries.file_history.kept_history_usage().ok()
            } else {
                None
            };
            let (kept_history_bytes, kept_history_versions) = match usage {
                Some((bytes, versions)) => (Some(bytes), Some(versions)),
                None => (None, None),
            };
            RespPayload::Gc(GcResponse {
                blocks_deleted: report.blocks_deleted,
                bytes_reclaimed: report.bytes_reclaimed,
                kept_history_bytes,
                kept_history_versions,
            })
        }
        Err(e) => RespPayload::Error(e.to_string()),
    }
}
