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
    EvictRequest, PauseDuration, PauseRequest, ReadoptVolumeRequest, RestoreVersionRequest,
    ResumeRequest, UpdateCheckRequest,
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
/// `PauseDuration` name (`PAUSE_DURATION_ONE_HOUR`, ...); the daemon computes
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
