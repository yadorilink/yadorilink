//! Folder Rewind: preview what rewinding a folder to an earlier time would
//! change, start the rewind the person approved, and read how the latest run
//! stands. Every front end drives these; the words a person reads for a run
//! or a refusal come from the daemon, except the answer for a run that can no
//! longer be followed (`dto::RUN_MISSING_MESSAGE`).

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::rewind_execute_response::Outcome;
use yadorilink_ipc_proto::daemonctl::{
    RewindActionCounts, RewindExecuteRequest, RewindPreviewRequest, RewindPreviewResponse,
    RewindRefused, RewindRun, RewindStatusRequest,
};

use crate::daemon::control;
use crate::error::CoreError;
use crate::ops::links::list_links;

/// How a request to start a rewind was answered. Nothing was started or
/// recorded unless it is [`RewindStart::Started`].
#[derive(Debug, Clone, PartialEq)]
pub enum RewindStart {
    Started {
        run_id: String,
    },
    /// The folder changed since the preview in a way that changes what the
    /// rewind would do; preview again.
    PlanStale {
        message: String,
        current_plan_id: Vec<u8>,
        current_counts: RewindActionCounts,
    },
    Refused(RewindRefused),
}

/// The linked folder `folder` names: a folder group id, or a local path of a
/// linked folder.
pub async fn resolve_folder_group(folder: &str) -> Result<String, CoreError> {
    let links = list_links().await?;
    if let Some(link) = links.iter().find(|l| l.group_id == folder) {
        return Ok(link.group_id.clone());
    }
    let canonical = std::fs::canonicalize(folder).ok().map(|p| p.to_string_lossy().to_string());
    links
        .iter()
        .find(|l| l.local_path == folder || canonical.as_deref() == Some(l.local_path.as_str()))
        .map(|l| l.group_id.clone())
        .ok_or_else(|| CoreError::InvalidInput(format!("{folder} is not a linked folder")))
}

/// What a rewind of `group_id` to `at_unix_nanos` (on the daemon device's
/// clock) would change. Changes nothing. `include_unchanged` also lists the
/// paths the rewind would leave alone.
pub async fn preview(
    group_id: String,
    at_unix_nanos: i64,
    include_unchanged: bool,
) -> Result<RewindPreviewResponse, CoreError> {
    let resp = control::send(ReqPayload::RewindPreview(RewindPreviewRequest {
        group_id,
        at_unix_nanos,
        include_unchanged,
    }))
    .await?;
    let Some(RespPayload::RewindPreview(plan)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    Ok(plan)
}

/// Starts the rewind a preview showed, named by its target time and plan id.
/// The daemon refuses a plan that no longer matches the folder; gathering
/// content and committing continue in the background (see [`status`]).
pub async fn execute(
    group_id: String,
    target_unix_nanos: i64,
    plan_id: Vec<u8>,
) -> Result<RewindStart, CoreError> {
    let resp = control::send(ReqPayload::RewindExecute(RewindExecuteRequest {
        group_id,
        target_unix_nanos,
        plan_id,
    }))
    .await?;
    let Some(RespPayload::RewindExecute(response)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    match response.outcome {
        Some(Outcome::Started(started)) => Ok(RewindStart::Started { run_id: started.run_id }),
        Some(Outcome::PlanStale(stale)) => Ok(RewindStart::PlanStale {
            message: stale.message,
            current_plan_id: stale.current_plan_id,
            current_counts: stale.current_counts.unwrap_or_default(),
        }),
        Some(Outcome::Refused(refused)) => Ok(RewindStart::Refused(refused)),
        None => Err(CoreError::Other("unexpected daemon response".into())),
    }
}

/// The folder's most recent rewind run, or `None` when it never had one.
pub async fn status(group_id: String) -> Result<Option<RewindRun>, CoreError> {
    let resp = control::send(ReqPayload::RewindStatus(RewindStatusRequest { group_id })).await?;
    let Some(RespPayload::RewindStatus(status)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    Ok(status.run)
}
