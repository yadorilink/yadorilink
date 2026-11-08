//! The `rewind` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

/// `yadorilink rewind <group> --at <timestamp>`: Folder Rewind's
/// read-only preview. Nothing here mutates anything -- no signed
/// change, no filesystem write, no obligation -- so it goes through
/// `queries`, not `application`, like every other read-only handler.
pub(super) async fn rewind_preview(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RewindPreviewRequest,
) -> RespPayload {
    match context.queries.rewind.preview(&r.group_id, r.at_unix_nanos, r.include_unchanged).await {
        Ok(preview) => RespPayload::RewindPreview(rewind_preview_to_proto(preview)),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

/// `yadorilink rewind ... --execute`: answered once the run is
/// recorded (or refused before anything is); the run itself goes on
/// in the background and is read back through `RewindStatus`.
pub(super) async fn rewind_execute(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RewindExecuteRequest,
) -> RespPayload {
    match <[u8; 32]>::try_from(r.plan_id.as_slice()) {
        Err(_) => RespPayload::Error("plan id must be 32 bytes".to_string()),
        Ok(plan_id) => {
            let request = crate::rewind::RewindExecuteRequest {
                group_id: r.group_id,
                target_unix_nanos: r.target_unix_nanos,
                plan_id: yadorilink_replica_domain::rewind::RewindPlanId(plan_id),
            };
            match context.application.rewind.execute(request).await {
                Ok(run_id) => RespPayload::RewindExecute(RewindExecuteResponse {
                    outcome: Some(RewindExecuteOutcome::Started(RewindRunStarted { run_id })),
                }),
                Err(error) => rewind_execute_refusal(error),
            }
        }
    }
}

pub(super) async fn rewind_status(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RewindStatusRequest,
) -> RespPayload {
    match context.queries.rewind.status(&r.group_id) {
        Ok(run) => {
            RespPayload::RewindStatus(RewindStatusResponse { run: run.map(rewind_run_to_proto) })
        }
        Err(e) => RespPayload::Error(e.to_string()),
    }
}
