//! The metered-network policy: whether peer traffic may flow on the connection the host reported.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    GetNetworkPolicyRequest, NetworkCost, NetworkPolicy, ReportNetworkCostRequest,
    SetSyncOnMeteredRequest,
};

use crate::daemon::control;
use crate::error::CoreError;

async fn send(payload: ReqPayload) -> Result<NetworkPolicy, CoreError> {
    let resp = control::send(payload).await?;
    let Some(RespPayload::NetworkPolicy(result)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    result.policy.ok_or_else(|| CoreError::Other("unexpected daemon response".into()))
}

/// The policy the daemon holds.
pub async fn network_policy() -> Result<NetworkPolicy, CoreError> {
    send(ReqPayload::GetNetworkPolicy(GetNetworkPolicyRequest {})).await
}

/// Allows or pauses sync on a metered connection; returns the policy now in force.
pub async fn set_sync_on_metered(enabled: bool) -> Result<NetworkPolicy, CoreError> {
    send(ReqPayload::SetSyncOnMetered(SetSyncOnMeteredRequest { enabled })).await
}

/// Tells the daemon what the connection is; returns the policy now in force.
pub async fn report_network_cost(cost: NetworkCost) -> Result<NetworkPolicy, CoreError> {
    send(ReqPayload::ReportNetworkCost(ReportNetworkCostRequest { cost: cost as i32 })).await
}
