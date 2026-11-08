//! Read-only endpoints.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ListAccountDevicesRequest, ListConflictsRequest, ListInboxRequest, ListLinksRequest,
    ListPreservedRequest, ListRetainedOriginalsRequest, ListSentTransfersRequest,
    ListShareEdgesRequest, ListTrashRequest, ListVersionsRequest, MaterializationStatusRequest,
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
        "paused_on_metered": status.paused_on_metered,
        "network_cost_known": status.network_cost_known,
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

/// The file's absolute path on this host, the form the write routes take.
/// Joined here, by the platform's own rules, so the page never guesses a
/// separator.
pub(super) fn absolute_path(local_path: &str, relative: &str) -> String {
    std::path::Path::new(local_path).join(relative).to_string_lossy().into_owned()
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
                "absolute_path": absolute_path(&f.local_path, &f.path),
                "size": f.size,
                "mtime_unix_nanos": f.mtime_unix_nanos,
                "kind": f.kind().as_str_name(),
                "reason": f.reason().as_str_name(),
                "resolvable": f.resolvable,
                "origin_device_id": f.origin_device_id,
            })
        })
        .collect();
    Ok(Json(json!({ "conflicts": conflicts })))
}

/// `GET /api/trash` -- `ListTrashRequest`: every recoverable deleted item
/// across all linked folders (`yadorilink trash list`).
pub async fn trash(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let resp = state.control.send(ReqPayload::ListTrash(ListTrashRequest {})).await?;
    let Some(RespPayload::ListTrash(list)) = resp.payload else {
        return Err(unexpected());
    };
    let files: Vec<Value> = list
        .files
        .iter()
        .map(|f| {
            json!({
                "local_path": f.local_path,
                "path": f.path,
                "absolute_path": absolute_path(&f.local_path, &f.path),
                "version_seq": f.version_seq,
                "size": f.last_known_size,
                "origin_device_id": f.origin_device_id,
                "deleted_at_unix_nanos": f.deleted_at_unix_nanos,
                "kind": f.kind().as_str_name(),
                "deleted_by_operation": f.deleted_by_operation,
            })
        })
        .collect();
    Ok(Json(json!({ "files": files })))
}

/// `GET /api/preserved` -- `ListPreservedRequest`: what a rebootstrap set
/// aside for the user to review (`yadorilink preserved list`).
pub async fn preserved(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let resp = state.control.send(ReqPayload::ListPreserved(ListPreservedRequest {})).await?;
    let Some(RespPayload::ListPreserved(list)) = resp.payload else {
        return Err(unexpected());
    };
    let items: Vec<Value> = list
        .items
        .iter()
        .map(|i| {
            json!({
                "kind": i.kind,
                "group_id": i.group_id,
                "group_removed": i.group_removed,
                "item_id": i.item_id,
                "path": i.path,
                "paths": i.paths,
                "content": i.content,
                "size": i.size,
                "blocks_held": i.blocks_held,
                "blocks_total": i.blocks_total,
                "recovery_id": i.recovery_id,
                "originals_quarantined": i.originals_quarantined,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// `GET /api/devices` -- `ListAccountDevicesRequest`: the account's devices by
/// name, so the page can say which device is which.
pub async fn devices(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let resp =
        state.control.send(ReqPayload::ListAccountDevices(ListAccountDevicesRequest {})).await?;
    let Some(RespPayload::ListAccountDevices(list)) = resp.payload else {
        return Err(unexpected());
    };
    let devices: Vec<Value> = list
        .devices
        .iter()
        .map(|d| {
            json!({
                "device_id": d.device_id,
                "device_name": d.device_name,
                "online": d.online,
                "is_this_device": d.is_this_device,
            })
        })
        .collect();
    Ok(Json(json!({ "devices": devices })))
}

/// `GET /api/shares` -- `ListShareEdgesRequest`: who is a member of which of
/// the account's folder groups, and whether they are active or waiting.
pub async fn shares(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let resp = state.control.send(ReqPayload::ListShareEdges(ListShareEdgesRequest {})).await?;
    let Some(RespPayload::ListShareEdges(list)) = resp.payload else {
        return Err(unexpected());
    };
    let edges: Vec<Value> = list
        .edges
        .iter()
        .map(|e| {
            json!({
                "edge_id": e.edge_id,
                "group_id": e.group_id,
                "device_id": e.device_id,
                "state": e.state,
            })
        })
        .collect();
    Ok(Json(json!({ "edges": edges })))
}

/// `GET /api/transfers` -- Track Send as the page shows it: `ListInboxRequest`
/// (offered to this device) and `ListSentTransfersRequest` (sent from it).
pub async fn transfers(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let inbox = state.control.send(ReqPayload::ListInbox(ListInboxRequest {})).await?;
    let Some(RespPayload::ListInbox(inbox)) = inbox.payload else {
        return Err(unexpected());
    };
    let sent =
        state.control.send(ReqPayload::ListSentTransfers(ListSentTransfersRequest {})).await?;
    let Some(RespPayload::ListSentTransfers(sent)) = sent.payload else {
        return Err(unexpected());
    };
    let files = |files: &[yadorilink_ipc_proto::daemonctl::InboxFileSummary]| {
        files.iter().map(|f| json!({ "path": f.relative_path, "size": f.size })).collect::<Vec<_>>()
    };
    let received: Vec<Value> = inbox
        .transfers
        .iter()
        .map(|t| {
            json!({
                "transfer_id": t.transfer_id,
                "device_id": t.sender_device_id,
                "files": files(&t.files),
                "total_size": t.total_size,
                "at_unix_nanos": t.offered_at_unix_nanos,
                "status": t.status,
                "failure": t.failure,
                "bytes_done": t.received_bytes,
                "destination_dir": t.destination_dir,
                "files_done": t.files_done,
                "files_total": t.files_total,
            })
        })
        .collect();
    let sent: Vec<Value> = sent
        .transfers
        .iter()
        .map(|t| {
            json!({
                "transfer_id": t.transfer_id,
                "device_id": t.target_device_id,
                "files": files(&t.files),
                "total_size": t.total_size,
                "at_unix_nanos": t.created_at_unix_nanos,
                "status": t.status,
                "failure": t.failure,
                "can_retry": t.can_retry,
                "bytes_done": t.bytes_sent,
            })
        })
        .collect();
    Ok(Json(json!({ "received": received, "sent": sent })))
}

/// `GET /api/retained` -- `ListRetainedOriginalsRequest`: originals a rebootstrap
/// kept under a claim because removing them could not be proved safe
/// (`yadorilink preserved retained list`).
pub async fn retained(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let resp = state
        .control
        .send(ReqPayload::ListRetainedOriginals(ListRetainedOriginalsRequest {}))
        .await?;
    let Some(RespPayload::ListRetainedOriginals(list)) = resp.payload else {
        return Err(unexpected());
    };
    let items: Vec<Value> = list
        .items
        .iter()
        .map(|i| {
            json!({
                "group_id": i.group_id,
                "group_removed": i.group_removed,
                "path": i.path,
                "size": i.size,
                "reachable": i.reachable,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
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
                "exec": v.exec,
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
