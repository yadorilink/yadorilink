//! Whole-app status and per-folder sync control.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    PauseDuration as WirePauseDuration, PauseRequest, ResumeRequest, StatusRequest, StatusResponse,
};

use crate::daemon::control;
use crate::dto::PauseDuration;
use crate::error::CoreError;
use crate::ops::links::list_links;

/// The daemon's whole-app status: folders, peers, transfers, limits,
/// storage, updates and recent errors.
pub async fn status() -> Result<StatusResponse, CoreError> {
    let resp = control::send(ReqPayload::Status(StatusRequest {})).await?;
    let Some(RespPayload::Status(status)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    Ok(status)
}

/// Pauses sync for one linked folder for `duration`. With `expected_group_id` the daemon pauses
/// only if the link at `local_path` still belongs to that group, and refuses with
/// `GroupMismatch` (changing nothing) otherwise.
pub async fn pause_folder(
    local_path: String,
    duration: PauseDuration,
    expected_group_id: Option<String>,
) -> Result<(), CoreError> {
    let duration = match duration {
        PauseDuration::UntilResumed => WirePauseDuration::Unspecified,
        PauseDuration::ThirtyMinutes => WirePauseDuration::ThirtyMinutes,
        PauseDuration::OneHour => WirePauseDuration::OneHour,
        PauseDuration::UntilTomorrow => WirePauseDuration::UntilTomorrow,
    };
    control::send(ReqPayload::Pause(PauseRequest {
        local_path,
        duration: duration as i32,
        expected_group_id: expected_group_id.unwrap_or_default(),
    }))
    .await?;
    Ok(())
}

/// Resumes sync for one linked folder; `expected_group_id` as for [`pause_folder`].
pub async fn resume_folder(
    local_path: String,
    expected_group_id: Option<String>,
) -> Result<(), CoreError> {
    control::send(ReqPayload::Resume(ResumeRequest {
        local_path,
        expected_group_id: expected_group_id.unwrap_or_default(),
    }))
    .await?;
    Ok(())
}

/// Pauses every currently linked folder. The control protocol tracks pause
/// per link, so this lists the links and pauses each, rather than adding a
/// "pause everything" daemon request.
pub async fn pause_all(duration: PauseDuration) -> Result<(), CoreError> {
    for link in list_links().await? {
        pause_folder(link.local_path, duration, None).await?;
    }
    Ok(())
}

/// Resumes every currently linked folder.
pub async fn resume_all() -> Result<(), CoreError> {
    for link in list_links().await? {
        resume_folder(link.local_path, None).await?;
    }
    Ok(())
}
