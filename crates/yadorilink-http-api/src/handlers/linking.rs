//! Linking a local folder: the preflight, then a plain link, a new shared
//! folder, a join or an invite acceptance. Each is the daemon request the
//! CLI's `link`, `share create`, `share join` and `share accept` send.
//!
//! `acknowledge_risks` is forwarded only as the caller sent it, and defaults
//! to `false`. The daemon runs the preflight itself and refuses an
//! unacknowledged risky folder, so this adapter adds no check of its own and
//! cannot skip that one. The page shows the preflight's warnings first and
//! sets the flag only after the user confirmed them.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    accept_invite_command_response, create_and_link_command_response,
    join_and_link_command_response, AcceptInviteCommandRequest, ApplicationCommandError,
    CreateAndLinkCommandRequest, EnrollmentCommandOutcome, JoinAndLinkCommandRequest,
    LinkPreflightRequest, LinkRequest, PendingEnrollmentKind,
};

use crate::error::ApiError;
use crate::AppState;

fn unexpected() -> ApiError {
    ApiError::Internal("daemon returned an unexpected response type for this request".into())
}

fn non_empty<'a>(value: &'a str, field: &str) -> Result<&'a str, ApiError> {
    if value.is_empty() {
        return Err(ApiError::BadRequest(format!("`{field}` must not be empty")));
    }
    Ok(value)
}

fn outcome_json(o: &EnrollmentCommandOutcome) -> Value {
    json!({
        "group_id": o.group_id,
        "local_path": o.local_path,
        "awaiting_approval": o.awaiting_approval,
        "already_linked": o.already_linked,
    })
}

fn command_error(e: ApplicationCommandError) -> ApiError {
    ApiError::DaemonRejected(e.message)
}

#[derive(Deserialize)]
pub struct PreflightBody {
    path: String,
}

/// `POST /api/link/preflight` `{"path": "<folder>"}` -- `LinkPreflightRequest`.
/// A `POST` only to keep the folder path out of URLs; it changes nothing.
pub async fn preflight(
    State(state): State<AppState>,
    Json(body): Json<PreflightBody>,
) -> Result<Json<Value>, ApiError> {
    let path = non_empty(&body.path, "path")?;
    let resp = state
        .control
        .send_long(ReqPayload::LinkPreflight(LinkPreflightRequest { local_path: path.to_string() }))
        .await?;
    let Some(RespPayload::LinkPreflight(r)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(Json(json!({
        "resolved_path": r.resolved_path,
        "warnings": r.warnings,
        "prohibitions": r.prohibitions,
    })))
}

#[derive(Deserialize)]
pub struct LinkBody {
    path: String,
    group_id: String,
    #[serde(default)]
    on_demand: bool,
    #[serde(default)]
    acknowledge_risks: bool,
}

/// `POST /api/link` `{"path", "group_id", "on_demand"?, "acknowledge_risks"?}`
/// -- `LinkRequest` for a group this account can already see.
pub async fn link(
    State(state): State<AppState>,
    Json(body): Json<LinkBody>,
) -> Result<Json<Value>, ApiError> {
    let resp = state
        .control
        .send_long(ReqPayload::Link(LinkRequest {
            local_path: non_empty(&body.path, "path")?.to_string(),
            group_id: non_empty(&body.group_id, "group_id")?.to_string(),
            on_demand: body.on_demand,
            acknowledge_risks: body.acknowledge_risks,
            // A plain link tracks no enrollment.
            pending_enrollment_operation_id: String::new(),
            pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
            pending_enrollment_device_id: String::new(),
        }))
        .await?;
    match resp.payload {
        Some(RespPayload::Link(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct CreateBody {
    path: String,
    group_name: String,
    #[serde(default)]
    on_demand: bool,
    #[serde(default)]
    acknowledge_risks: bool,
}

/// `POST /api/share/create` `{"path", "group_name", "on_demand"?, "acknowledge_risks"?}`
/// -- `CreateAndLinkCommandRequest`: a new folder group, linked here.
pub async fn create(
    State(state): State<AppState>,
    Json(body): Json<CreateBody>,
) -> Result<Json<Value>, ApiError> {
    let resp = state
        .control
        .send_long(ReqPayload::CreateAndLinkCommand(CreateAndLinkCommandRequest {
            group_name: non_empty(&body.group_name, "group_name")?.to_string(),
            local_path: non_empty(&body.path, "path")?.to_string(),
            on_demand: body.on_demand,
            acknowledge_risks: body.acknowledge_risks,
            provider_display_name: String::new(),
            request_token: String::new(),
            create_local_path_if_missing: false,
        }))
        .await?;
    let Some(RespPayload::CreateAndLinkCommand(r)) = resp.payload else {
        return Err(unexpected());
    };
    match r.result {
        Some(create_and_link_command_response::Result::Outcome(o)) => Ok(Json(outcome_json(&o))),
        Some(create_and_link_command_response::Result::Error(e)) => Err(command_error(e)),
        None => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct JoinBody {
    path: String,
    group_id: String,
    #[serde(default)]
    group_name: String,
    #[serde(default)]
    on_demand: bool,
    #[serde(default)]
    acknowledge_risks: bool,
}

/// `POST /api/share/join` `{"path", "group_id", "group_name"?, "on_demand"?, "acknowledge_risks"?}`
/// -- `JoinAndLinkCommandRequest` for a group of this account.
pub async fn join(
    State(state): State<AppState>,
    Json(body): Json<JoinBody>,
) -> Result<Json<Value>, ApiError> {
    let resp = state
        .control
        .send_long(ReqPayload::JoinAndLinkCommand(JoinAndLinkCommandRequest {
            group_id: non_empty(&body.group_id, "group_id")?.to_string(),
            group_name: body.group_name,
            local_path: non_empty(&body.path, "path")?.to_string(),
            on_demand: body.on_demand,
            acknowledge_risks: body.acknowledge_risks,
            provider_display_name: String::new(),
            request_token: String::new(),
        }))
        .await?;
    let Some(RespPayload::JoinAndLinkCommand(r)) = resp.payload else {
        return Err(unexpected());
    };
    match r.result {
        Some(join_and_link_command_response::Result::Outcome(o)) => Ok(Json(outcome_json(&o))),
        Some(join_and_link_command_response::Result::Error(e)) => Err(command_error(e)),
        None => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct AcceptBody {
    path: String,
    code: String,
    #[serde(default)]
    on_demand: bool,
    #[serde(default)]
    acknowledge_risks: bool,
}

/// `POST /api/invite/accept` `{"path", "code", "on_demand"?, "acknowledge_risks"?}`
/// -- `AcceptInviteCommandRequest`. The code travels only in this body.
pub async fn accept_invite(
    State(state): State<AppState>,
    Json(body): Json<AcceptBody>,
) -> Result<Json<Value>, ApiError> {
    let resp = state
        .control
        .send_long(ReqPayload::AcceptInviteCommand(AcceptInviteCommandRequest {
            code: non_empty(body.code.trim(), "code")?.to_string(),
            local_path: non_empty(&body.path, "path")?.to_string(),
            on_demand: body.on_demand,
            acknowledge_risks: body.acknowledge_risks,
        }))
        .await?;
    let Some(RespPayload::AcceptInviteCommand(r)) = resp.payload else {
        return Err(unexpected());
    };
    match r.result {
        Some(accept_invite_command_response::Result::Outcome(o)) => Ok(Json(outcome_json(&o))),
        Some(accept_invite_command_response::Result::Error(e)) => Err(command_error(e)),
        None => Err(unexpected()),
    }
}
