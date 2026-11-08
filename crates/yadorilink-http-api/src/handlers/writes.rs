//! Mutating endpoints. Every one of these is a direct translation of
//! an existing `DaemonControlRequest` variant that already has a CLI
//! counterpart (`yadorilink pause`/`resume`/`evict`/`restore`) -- no new
//! daemon capability is introduced. `/api/resume` is added here because it
//! is the direct, symmetric IPC counterpart of `/api/pause` (`ResumeRequest`
//! already exists and is already dispatched by `control_socket.rs`):
//! without it, a caller could pause a folder through this API but never
//! reverse it through the same API. This crate
//! only ever adds an endpoint when it has a direct existing IPC
//! counterpart to translate -- it does not introduce new daemon
//! capabilities.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    delete_group_command_response, remove_device_command_response, resolve_conflict_response,
    revoke_device_command_response, ApplicationErrorCode, CancelTransferRequest,
    ConflictResolution, DeleteGroupCommandRequest, DiscardPreservedRequest, EvictRequest,
    PauseDuration, PauseRequest, ReadoptVolumeRequest, ReleaseRetainedOriginalsRequest,
    RemoveDeviceCommandRequest, ReplicaMembershipCommandOutcome, ResolveConflictRequest,
    RestorePreservedRequest, RestoreTrashOperationRequest, RestoreTrashRequest,
    RestoreVersionRequest, ResumeRequest, RetryDirection, RetryPreservedRequest,
    RetryTransferRequest, RevokeDeviceCommandRequest, UnlinkRequest, UpdateCheckRequest,
};

use crate::error::ApiError;
use crate::AppState;

fn unexpected() -> ApiError {
    ApiError::Internal("daemon returned an unexpected response type for this request".into())
}

#[derive(Deserialize)]
pub struct LocalPathBody {
    path: String,
}

/// `POST /api/pause` body: the folder, plus an optional pause length named by
/// the protocol's own `PauseDuration` identifier (absent means until resumed).
#[derive(Deserialize)]
pub struct PauseBody {
    path: String,
    duration: Option<String>,
}

fn require_path(body: &LocalPathBody) -> Result<&str, ApiError> {
    if body.path.is_empty() {
        return Err(ApiError::BadRequest("`path` must not be empty".into()));
    }
    Ok(&body.path)
}

/// `POST /api/pause` `{"path": "<local folder path>", "duration": "<optional>"}`
/// -- `PauseRequest` takes the link's local path (not an absolute file path
/// under it), same as `yadorilink pause <path>`. `duration` is a
/// `PauseDuration` name (`PAUSE_DURATION_TWO_HOURS`, ...); the daemon computes
/// the deadline.
pub async fn pause(
    State(state): State<AppState>,
    Json(body): Json<PauseBody>,
) -> Result<Json<Value>, ApiError> {
    if body.path.is_empty() {
        return Err(ApiError::BadRequest("`path` must not be empty".into()));
    }
    let duration = match body.duration.as_deref() {
        None => PauseDuration::Unspecified,
        Some(name) => PauseDuration::from_str_name(name)
            .ok_or_else(|| ApiError::BadRequest(format!("unknown pause duration `{name}`")))?,
    };
    let resp = state
        .control
        .send(ReqPayload::Pause(PauseRequest {
            local_path: body.path,
            duration: duration as i32,
            expected_group_id: String::new(),
        }))
        .await?;
    match resp.payload {
        Some(RespPayload::Pause(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

/// `POST /api/resume` `{"path": "<local folder path>"}`.
pub async fn resume(
    State(state): State<AppState>,
    Json(body): Json<LocalPathBody>,
) -> Result<Json<Value>, ApiError> {
    let path = require_path(&body)?;
    let resp = state
        .control
        .send(ReqPayload::Resume(ResumeRequest {
            local_path: path.to_string(),
            expected_group_id: String::new(),
        }))
        .await?;
    match resp.payload {
        Some(RespPayload::Resume(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct UnlinkBody {
    path: String,
    /// The group the page showed for this folder; the daemon refuses, changing
    /// nothing, if the link has meanwhile moved to another group.
    #[serde(default)]
    group_id: String,
}

/// `POST /api/unlink` `{"path": "<local folder path>", "group_id": "<optional>"}`
/// -- `UnlinkRequest`, same as `yadorilink unlink <path>`. The daemon's own
/// refusal to drop the last complete copy still applies; the `--force`
/// override is deliberately not offered here.
pub async fn unlink(
    State(state): State<AppState>,
    Json(body): Json<UnlinkBody>,
) -> Result<Json<Value>, ApiError> {
    if body.path.is_empty() {
        return Err(ApiError::BadRequest("`path` must not be empty".into()));
    }
    let resp = state
        .control
        .send_long(ReqPayload::Unlink(UnlinkRequest {
            local_path: body.path,
            force: false,
            expected_group_id: body.group_id,
        }))
        .await?;
    match resp.payload {
        Some(RespPayload::Unlink(_)) => Ok(Json(json!({ "ok": true }))),
        // Not the last complete copy, wrong group, or terms to accept first.
        Some(RespPayload::CommandError(e)) => Err(ApiError::DaemonRejected(e.message)),
        _ => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct ResolveBody {
    /// Absolute path of the conflict copy, as `/api/conflicts` lists it.
    path: String,
    /// `keep_this` or `keep_both`.
    resolution: String,
}

/// `POST /api/conflicts/resolve` `{"path": "<conflict copy>", "resolution": "keep_this"|"keep_both"}`
/// -- `ResolveConflictRequest`, same as `yadorilink conflicts keep` /
/// `keep-both`. The daemon decides at the moment it runs and refuses a copy
/// that is no longer resolvable or whose files hold unrecorded changes.
pub async fn resolve_conflict(
    State(state): State<AppState>,
    Json(body): Json<ResolveBody>,
) -> Result<Json<Value>, ApiError> {
    if body.path.is_empty() {
        return Err(ApiError::BadRequest("`path` must not be empty".into()));
    }
    let resolution = match body.resolution.as_str() {
        "keep_this" => ConflictResolution::KeepThis,
        "keep_both" => ConflictResolution::KeepBoth,
        other => {
            return Err(ApiError::BadRequest(format!("unknown resolution `{other}`")));
        }
    };
    let resp = state
        .control
        .send(ReqPayload::ResolveConflict(ResolveConflictRequest {
            copy_path: body.path,
            resolution: resolution as i32,
        }))
        .await?;
    let Some(RespPayload::ResolveConflict(r)) = resp.payload else {
        return Err(unexpected());
    };
    match r.result {
        Some(resolve_conflict_response::Result::KeptPath(p)) => Ok(Json(json!({ "kept_path": p }))),
        Some(resolve_conflict_response::Result::Error(e)) => {
            Err(ApiError::DaemonRejected(e.message))
        }
        None => Err(unexpected()),
    }
}

/// `POST /api/readopt` `{"path": "<local folder path>"}` -- the user confirms
/// that the disk now mounted at the linked folder is that folder's disk
/// (`ReadoptVolumeRequest`), same as `yadorilink readopt <path>`.
pub async fn readopt(
    State(state): State<AppState>,
    Json(body): Json<LocalPathBody>,
) -> Result<Json<Value>, ApiError> {
    let path = require_path(&body)?;
    let resp = state
        .control
        .send(ReqPayload::ReadoptVolume(ReadoptVolumeRequest { local_path: path.to_string() }))
        .await?;
    match resp.payload {
        Some(RespPayload::ReadoptVolume(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

/// `POST /api/evict` `{"path": "<absolute file or folder path>"}` -- returns whether
/// anything was actually freed (see `EvictResponse.dehydrated`'s own doc
/// comment in the proto: a bare "ok" here would silently overclaim
/// success).
pub async fn evict(
    State(state): State<AppState>,
    Json(body): Json<LocalPathBody>,
) -> Result<Json<Value>, ApiError> {
    let path = require_path(&body)?;
    let resp = state
        .control
        .send(ReqPayload::Evict(EvictRequest { absolute_path: path.to_string() }))
        .await?;
    let Some(RespPayload::Evict(e)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(Json(json!({
        "dehydrated": e.dehydrated,
        "blocks_reclaimed": e.blocks_reclaimed,
        "bytes_reclaimed": e.bytes_reclaimed,
    })))
}

#[derive(Deserialize)]
pub struct RestoreBody {
    path: String,
    /// Absent restores the most recent superseded version, matching
    /// `yadorilink restore <path>` with no `--version` flag.
    version_seq: Option<i64>,
}

/// `POST /api/restore` `{"path": "<absolute file path>", "version_seq": <optional i64>}`.
pub async fn restore(
    State(state): State<AppState>,
    Json(body): Json<RestoreBody>,
) -> Result<Json<Value>, ApiError> {
    if body.path.is_empty() {
        return Err(ApiError::BadRequest("`path` must not be empty".into()));
    }
    let resp = state
        .control
        .send(ReqPayload::RestoreVersion(RestoreVersionRequest {
            absolute_path: body.path,
            version_seq: body.version_seq,
        }))
        .await?;
    match resp.payload {
        Some(RespPayload::RestoreVersion(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct TrashRestoreBody {
    path: String,
    /// Restore everything the same recursive delete removed, not just this entry.
    #[serde(default)]
    whole_operation: bool,
}

/// `POST /api/trash/restore` `{"path": "<absolute path>", "whole_operation"?: bool}`
/// -- `RestoreTrashRequest`, or `RestoreTrashOperationRequest` when
/// `whole_operation` is set (`yadorilink trash restore [--folder]`).
pub async fn trash_restore(
    State(state): State<AppState>,
    Json(body): Json<TrashRestoreBody>,
) -> Result<Json<Value>, ApiError> {
    if body.path.is_empty() {
        return Err(ApiError::BadRequest("`path` must not be empty".into()));
    }
    if body.whole_operation {
        let resp = state
            .control
            .send(ReqPayload::RestoreTrashOperation(RestoreTrashOperationRequest {
                absolute_path: body.path,
            }))
            .await?;
        let Some(RespPayload::RestoreTrashOperation(r)) = resp.payload else {
            return Err(unexpected());
        };
        return Ok(Json(json!({
            "restored_paths": r.restored_paths,
            "failed": r.failed.iter().map(|f| json!({ "path": f.path, "error": f.error })).collect::<Vec<_>>(),
            "partial": r.partial,
        })));
    }
    let resp = state
        .control
        .send(ReqPayload::RestoreTrash(RestoreTrashRequest { absolute_path: body.path }))
        .await?;
    match resp.payload {
        Some(RespPayload::RestoreTrash(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct RemoveDeviceBody {
    device_id: String,
}

/// `POST /api/devices/remove` `{"device_id": "<id>"}` -- `RemoveDeviceCommandRequest`
/// without `force`: the daemon refuses while the removal would leave a folder
/// without a confirmed complete copy, and the page has no way around that.
pub async fn remove_device(
    State(state): State<AppState>,
    Json(body): Json<RemoveDeviceBody>,
) -> Result<Json<Value>, ApiError> {
    if body.device_id.is_empty() {
        return Err(ApiError::BadRequest("`device_id` must not be empty".into()));
    }
    let resp = state
        .control
        .send_long(ReqPayload::RemoveDeviceCommand(RemoveDeviceCommandRequest {
            device_id: body.device_id,
            force: false,
        }))
        .await?;
    let Some(RespPayload::RemoveDeviceCommand(r)) = resp.payload else {
        return Err(unexpected());
    };
    match r.result {
        Some(remove_device_command_response::Result::Outcome(o)) => Ok(Json(removal_json(&o))),
        Some(remove_device_command_response::Result::Error(e)) => {
            // The account may have applied the removal even though the answer
            // was lost: say so instead of presenting a refusal that is safe to repeat.
            if matches!(
                e.code(),
                ApplicationErrorCode::CoordinationAmbiguous
                    | ApplicationErrorCode::CoordinationTransport
            ) {
                return Err(ApiError::StillRunning);
            }
            Err(ApiError::DaemonRejected(e.message))
        }
        None => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct RevokeMemberBody {
    group_id: String,
    device_id: String,
}

/// `POST /api/share/revoke` `{"group_id", "device_id"}` -- `RevokeDeviceCommandRequest`
/// without `force`, same as `yadorilink share revoke`: the daemon refuses while the
/// revoke would leave the member's data without another complete copy, and the page
/// has no way around that. Answers like a device removal, with the handoff leases.
pub async fn revoke_member(
    State(state): State<AppState>,
    Json(body): Json<RevokeMemberBody>,
) -> Result<Json<Value>, ApiError> {
    if body.group_id.is_empty() || body.device_id.is_empty() {
        return Err(ApiError::BadRequest("`group_id` and `device_id` must not be empty".into()));
    }
    let resp = state
        .control
        .send_long(ReqPayload::RevokeDeviceCommand(RevokeDeviceCommandRequest {
            group_id: body.group_id,
            device_id: body.device_id,
            force: false,
        }))
        .await?;
    let Some(RespPayload::RevokeDeviceCommand(r)) = resp.payload else {
        return Err(unexpected());
    };
    match r.result {
        Some(revoke_device_command_response::Result::Outcome(o)) => Ok(Json(removal_json(&o))),
        Some(revoke_device_command_response::Result::Error(e)) => {
            if matches!(
                e.code(),
                ApplicationErrorCode::CoordinationAmbiguous
                    | ApplicationErrorCode::CoordinationTransport
            ) {
                return Err(ApiError::StillRunning);
            }
            Err(ApiError::DaemonRejected(e.message))
        }
        None => Err(unexpected()),
    }
}

/// What a removal answers on success: `ok`, plus the handoff leases the daemon
/// took so each folder keeps a complete copy somewhere (`group_id`, the device
/// now holding it, the lease and the membership generation it was taken at).
fn removal_json(outcome: &ReplicaMembershipCommandOutcome) -> Value {
    let handoffs: Vec<Value> = outcome
        .handoffs
        .iter()
        .map(|h| {
            json!({
                "group_id": h.group_id,
                "target_device_id": h.target_device_id,
                "lease_id": h.lease_id,
                "membership_generation": h.membership_generation,
            })
        })
        .collect();
    json!({ "ok": true, "handoffs": handoffs })
}

#[derive(Deserialize)]
pub struct TransferBody {
    transfer_id: String,
    /// `sent` or `received`: retry only. A retry meant for a received transfer
    /// must never offer a sent one, or the reverse, so the page always says.
    direction: Option<String>,
}

/// `POST /api/transfers/cancel` `{"transfer_id"}` -- `CancelTransferRequest`,
/// whichever side this device is on. Idempotent.
pub async fn cancel_transfer(
    State(state): State<AppState>,
    Json(body): Json<TransferBody>,
) -> Result<Json<Value>, ApiError> {
    if body.transfer_id.is_empty() {
        return Err(ApiError::BadRequest("`transfer_id` must not be empty".into()));
    }
    let resp = state
        .control
        .send(ReqPayload::CancelTransfer(CancelTransferRequest { transfer_id: body.transfer_id }))
        .await?;
    match resp.payload {
        Some(RespPayload::CancelTransfer(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

/// `POST /api/transfers/retry` `{"transfer_id", "direction": "sent"|"received"}`
/// -- `RetryTransferRequest`. A received transfer is resumed (this can take as
/// long as the network does: `StillRunning` means it carries on in the daemon);
/// a sent one is offered again.
pub async fn retry_transfer(
    State(state): State<AppState>,
    Json(body): Json<TransferBody>,
) -> Result<Json<Value>, ApiError> {
    if body.transfer_id.is_empty() {
        return Err(ApiError::BadRequest("`transfer_id` must not be empty".into()));
    }
    let direction = match body.direction.as_deref() {
        Some("sent") => RetryDirection::Sent,
        Some("received") => RetryDirection::Received,
        _ => {
            return Err(ApiError::BadRequest("`direction` must be `sent` or `received`".into()));
        }
    };
    let resp = state
        .control
        .send_long(ReqPayload::RetryTransfer(RetryTransferRequest {
            transfer_id: body.transfer_id,
            direction: direction as i32,
        }))
        .await?;
    match resp.payload {
        Some(RespPayload::RetryTransfer(r)) => Ok(Json(json!({
            "offered": r.offered,
            "files_received": r.files_received.len(),
            "bytes_received": r.bytes_received,
            "files_offered": r.files_offered.len(),
            "total_size": r.total_size,
        }))),
        Some(RespPayload::CommandError(e)) => Err(ApiError::DaemonRejected(e.message)),
        _ => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct ReleaseRetainedBody {
    group_id: String,
}

/// `POST /api/retained/free` `{"group_id"}` -- `ReleaseRetainedOriginalsRequest`,
/// same as `yadorilink preserved retained release <group>`. The daemon releases
/// only what it can prove safe and answers per file; the rest stays.
pub async fn release_retained(
    State(state): State<AppState>,
    Json(body): Json<ReleaseRetainedBody>,
) -> Result<Json<Value>, ApiError> {
    if body.group_id.is_empty() {
        return Err(ApiError::BadRequest("`group_id` must not be empty".into()));
    }
    let resp = state
        .control
        .send_long(ReqPayload::ReleaseRetainedOriginals(ReleaseRetainedOriginalsRequest {
            group_id: body.group_id,
        }))
        .await?;
    let Some(RespPayload::ReleaseRetainedOriginals(done)) = resp.payload else {
        return Err(unexpected());
    };
    let releases: Vec<Value> = done
        .releases
        .iter()
        .map(|r| json!({ "path": r.path, "outcome": r.outcome, "detail": r.detail }))
        .collect();
    Ok(Json(json!({ "results": releases })))
}

#[derive(Deserialize)]
pub struct DeleteGroupBody {
    group_id: String,
    /// The user confirmed that members on other accounts lose access too. The
    /// coordination plane refuses a group that has any without it.
    #[serde(default)]
    acknowledge_cross_account_members: bool,
}

/// `POST /api/share/delete` `{"group_id", "acknowledge_cross_account_members"?}`
/// -- `DeleteGroupCommandRequest`, same as `yadorilink share delete`. Terminal:
/// the group and every member's access to it are gone; files already on each
/// device stay on its disk. The plane's own refusal (not the owner, members on
/// other accounts not acknowledged) comes back verbatim.
pub async fn delete_group(
    State(state): State<AppState>,
    Json(body): Json<DeleteGroupBody>,
) -> Result<Json<Value>, ApiError> {
    if body.group_id.is_empty() {
        return Err(ApiError::BadRequest("`group_id` must not be empty".into()));
    }
    let resp = state
        .control
        .send_long(ReqPayload::DeleteGroupCommand(DeleteGroupCommandRequest {
            group_id: body.group_id,
            acknowledge_cross_account_members: body.acknowledge_cross_account_members,
        }))
        .await?;
    let Some(RespPayload::DeleteGroupCommand(r)) = resp.payload else {
        return Err(unexpected());
    };
    match r.result {
        Some(delete_group_command_response::Result::Ok(_)) => Ok(Json(json!({ "ok": true }))),
        Some(delete_group_command_response::Result::Error(message)) => {
            Err(ApiError::DaemonRejected(message))
        }
        None => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct PreservedBody {
    group_id: String,
    item_id: String,
    /// `restore`, `retry` (an own change a rebootstrap held back) or `discard`.
    action: String,
}

/// `POST /api/preserved/action` `{"group_id", "item_id", "action": "restore"|"retry"|"discard"}`
/// -- `RestorePreservedRequest` (writes the item back at its original path as
/// an ordinary new write) or `DiscardPreservedRequest` (the only way a
/// preserved item is ever deleted).
pub async fn preserved_action(
    State(state): State<AppState>,
    Json(body): Json<PreservedBody>,
) -> Result<Json<Value>, ApiError> {
    if body.group_id.is_empty() || body.item_id.is_empty() {
        return Err(ApiError::BadRequest("`group_id` and `item_id` must not be empty".into()));
    }
    let resp = match body.action.as_str() {
        "restore" => {
            state
                .control
                .send(ReqPayload::RestorePreserved(RestorePreservedRequest {
                    group_id: body.group_id,
                    item_id: body.item_id,
                }))
                .await?
        }
        "retry" => {
            state
                .control
                .send(ReqPayload::RetryPreserved(RetryPreservedRequest {
                    group_id: body.group_id,
                    item_id: body.item_id,
                }))
                .await?
        }
        "discard" => {
            state
                .control
                .send(ReqPayload::DiscardPreserved(DiscardPreservedRequest {
                    group_id: body.group_id,
                    item_id: body.item_id,
                }))
                .await?
        }
        other => return Err(ApiError::BadRequest(format!("unknown action `{other}`"))),
    };
    match resp.payload {
        Some(
            RespPayload::RestorePreserved(_)
            | RespPayload::DiscardPreserved(_)
            | RespPayload::RetryPreserved(_),
        ) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

/// `POST /api/update/check` -- `UpdateCheckRequest`, the same manual check
/// `yadorilink update check` runs. A `POST` because it is not a read: the
/// daemon makes a network request and records the result. The page only
/// sends it on an explicit click, never on load or refresh.
pub async fn update_check(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let resp = state.control.send_long(ReqPayload::UpdateCheck(UpdateCheckRequest {})).await?;
    let Some(RespPayload::UpdateCheck(r)) = resp.payload else {
        return Err(unexpected());
    };
    let s = r.status.unwrap_or_default();
    Ok(Json(json!({
        "state": s.state,
        "current_version": s.current_version,
        "channel": s.channel,
        "install_source": s.install_source,
        "last_check_unix": s.last_check_unix,
        "available_version": s.available_version,
        "release_notes_url": s.release_notes_url,
        "mandatory": s.mandatory,
        "update_required": s.update_required,
        "holdback_reason": s.holdback_reason,
        "last_error_category": s.last_error_category,
        "last_error_message": s.last_error_message,
        "manifest_generated_at": s.manifest_generated_at,
        "last_success_unix": s.last_success_unix,
        "manifest_expires_at": s.manifest_expires_at,
        "manifest_expired": s.manifest_expired,
    })))
}

#[cfg(test)]
mod removal_tests {
    use super::*;
    use yadorilink_ipc_proto::daemonctl::MembershipHandoffResult;

    #[test]
    fn a_removal_answer_carries_the_handoff_leases() {
        let none = removal_json(&ReplicaMembershipCommandOutcome::default());
        assert_eq!(none, json!({ "ok": true, "handoffs": [] }));

        let outcome = ReplicaMembershipCommandOutcome {
            handoffs: vec![MembershipHandoffResult {
                group_id: "g1".into(),
                target_device_id: "dev-b".into(),
                lease_id: "lease-1".into(),
                membership_generation: 7,
            }],
            ..Default::default()
        };
        assert_eq!(
            removal_json(&outcome),
            json!({ "ok": true, "handoffs": [{
                "group_id": "g1", "target_device_id": "dev-b",
                "lease_id": "lease-1", "membership_generation": 7 }] })
        );
    }
}
