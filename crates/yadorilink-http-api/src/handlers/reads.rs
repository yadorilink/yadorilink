//! Read-only endpoints.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ListConflictsRequest, ListLinksRequest, ListVersionsRequest, MaterializationStatusRequest,
    StatusRequest,
};

use super::{link_status_json, local_state_json, peer_status_json};
use crate::error::ApiError;
use crate::AppState;

fn unexpected() -> ApiError {
    ApiError::Internal("daemon returned an unexpected response type for this request".into())
}

pub fn status_response_json(status: &yadorilink_ipc_proto::daemonctl::StatusResponse) -> Value {
    json!({
        "links": status.links.iter().map(link_status_json).collect::<Vec<_>>(),
        "peers": status.peers.iter().map(peer_status_json).collect::<Vec<_>>(),
        "upload_limit_bytes_per_sec": status.upload_limit_bytes_per_sec,
        "download_limit_bytes_per_sec": status.download_limit_bytes_per_sec,
        "current_upload_bytes_per_sec": status.current_upload_bytes_per_sec,
        "current_download_bytes_per_sec": status.current_download_bytes_per_sec,
        "volumes": status.volumes.iter().map(|v| json!({
            "path": v.path,
            "state": v.state,
            "available_bytes": v.available_bytes,
            "headroom_bytes": v.headroom_bytes,
            "total_bytes": v.total_bytes,
        })).collect::<Vec<_>>(),
        "update": {
            "state": status.update_state,
            "available_version": status.update_available_version,
            "mandatory": status.update_mandatory,
            "update_required": status.update_required,
            "last_error_category": status.update_last_error_category,
            "channel": status.update_channel,
            "install_source": status.update_install_source,
            "holdback_reason": status.update_holdback_reason,
        },
        "block_store": {
            "total_bytes": status.block_store_total_bytes,
            "block_count": status.block_store_block_count,
            "last_gc_unix": status.last_gc_unix,
            "gc_reclaimable_estimate_bytes": status.gc_reclaimable_estimate_bytes,
        },
        "active_transfers": status.active_transfers.iter().map(|t| json!({
            "group_id": t.group_id,
            "path": t.path,
            "bytes_done": t.bytes_done,
            "bytes_total": t.bytes_total,
            "blocks_done": t.blocks_done,
            "blocks_total": t.blocks_total,
            "source_peer": t.source_peer,
            "started_at_unix": t.started_at_unix,
        })).collect::<Vec<_>>(),
        "recent_errors": status.recent_errors.iter().map(|e| json!({
            "category": e.category,
            "timestamp_unix": e.timestamp_unix,
            "coarse_context": e.coarse_context,
        })).collect::<Vec<_>>(),
        "overall_state": status.overall_state,
        "attention_reasons": status.attention_reasons,
    })
}

/// `GET /api/status` -- direct translation of `StatusRequest`/`StatusResponse`.
pub async fn status(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let resp = state.control.send(ReqPayload::Status(StatusRequest {})).await?;
    let Some(RespPayload::Status(status)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(Json(status_response_json(&status)))
}

/// `GET /api/links` -- direct translation of `ListLinksRequest`/`ListLinksResponse`.
pub async fn links(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let resp = state.control.send(ReqPayload::ListLinks(ListLinksRequest {})).await?;
    let Some(RespPayload::ListLinks(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(Json(json!({ "links": list.links.iter().map(link_status_json).collect::<Vec<_>>() })))
}

/// `GET /api/conflicts` -- direct translation of `ListConflictsRequest`/
/// `ListConflictsResponse` (`yadorilink conflicts list`'s own IPC): one row
/// per currently-live conflicted-copy file, spanning every linked folder at
/// once, same shape as `ListTrash`/`ListLinks`/`Status` above.
pub async fn conflicts(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let resp = state.control.send(ReqPayload::ListConflicts(ListConflictsRequest {})).await?;
    let Some(RespPayload::ListConflicts(list)) = resp.payload else {
        return Err(unexpected());
    };
    let conflicts: Vec<Value> = list
        .files
        .iter()
        .map(|f| {
            json!({
                "local_path": f.local_path,
                "path": f.path,
                "size": f.size,
                "mtime_unix_nanos": f.mtime_unix_nanos,
                "kind": f.kind().as_str_name(),
                "reason": f.reason().as_str_name(),
            })
        })
        .collect();
    Ok(Json(json!({ "conflicts": conflicts })))
}

/// `GET /api/connections` -- the peer list from `StatusRequest`/`StatusResponse`
/// (`StatusResponse.peers`), the same data `yadorilink status` already
/// prints per peer. Distinct from `ListConnectionTraces`/`ConnectivityDoctor`
/// (historical connection-attempt/diagnostic data), which this adapter does
/// not currently expose -- `/api/connections` answers "who am I connected to
/// right now," not "what connection attempts have I made."
pub async fn connections(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let resp = state.control.send(ReqPayload::Status(StatusRequest {})).await?;
    let Some(RespPayload::Status(status)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(Json(
        json!({ "connections": status.peers.iter().map(peer_status_json).collect::<Vec<_>>() }),
    ))
}

#[derive(Deserialize)]
pub struct PathQuery {
    path: Option<String>,
}

fn require_path(q: &PathQuery) -> Result<&str, ApiError> {
    match q.path.as_deref() {
        Some(p) if !p.is_empty() => Ok(p),
        _ => Err(ApiError::BadRequest("query parameter `path` is required".into())),
    }
}

/// `GET /api/versions?path=...` -- direct translation of
/// `ListVersionsRequest`/`ListVersionsResponse`.
pub async fn versions(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
) -> Result<Json<Value>, ApiError> {
    let path = require_path(&q)?;
    let resp = state
        .control
        .send(ReqPayload::ListVersions(ListVersionsRequest { absolute_path: path.to_string() }))
        .await?;
    let Some(RespPayload::ListVersions(list)) = resp.payload else {
        return Err(unexpected());
    };
    let versions: Vec<Value> = list
        .versions
        .iter()
        .map(|v| {
            json!({
                "version_seq": v.version_seq,
                "size": v.size,
                "mtime_unix_nanos": v.mtime_unix_nanos,
                "state": v.state,
                "origin_device_id": v.origin_device_id,
                "unix_mode": v.unix_mode,
                "kind": v.kind().as_str_name(),
            })
        })
        .collect();
    Ok(Json(json!({ "versions": versions })))
}

/// `GET /api/materialization?path=...` -- direct translation of
/// `MaterializationStatusRequest`/`MaterializationStatusResponse`.
pub async fn materialization(
    State(state): State<AppState>,
    Query(q): Query<PathQuery>,
) -> Result<Json<Value>, ApiError> {
    let path = require_path(&q)?;
    let resp = state
        .control
        .send(ReqPayload::MaterializationStatus(MaterializationStatusRequest {
            absolute_path: path.to_string(),
        }))
        .await?;
    let Some(RespPayload::MaterializationStatus(m)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(Json(json!({
        "known": m.known,
        "local_state": local_state_json(m.local_state.as_ref()),
    })))
}
