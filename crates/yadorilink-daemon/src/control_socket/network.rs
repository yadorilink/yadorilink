//! The `network` family of control verbs: the metered-network policy.

use super::*;
use yadorilink_ipc_proto::daemonctl::{
    NetworkCost as WireCost, NetworkPolicy as WirePolicy, NetworkPolicyResponse,
    ReportNetworkCostRequest, SetSyncOnMeteredRequest,
};

use crate::network_policy::{NetworkCost, PolicyState};

fn to_wire(state: PolicyState) -> RespPayload {
    let cost = match state.cost {
        NetworkCost::Unknown => WireCost::Unknown,
        NetworkCost::Unmetered => WireCost::Unmetered,
        NetworkCost::Metered => WireCost::Metered,
    };
    RespPayload::NetworkPolicy(NetworkPolicyResponse {
        policy: Some(WirePolicy {
            sync_on_metered: state.sync_on_metered,
            cost: cost as i32,
            paused_on_metered: state.paused_on_metered(),
        }),
    })
}

pub(super) async fn get_network_policy(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    to_wire(context.network_policy.current())
}

pub(super) async fn set_sync_on_metered(
    context: &crate::control_context::ControlContext,
    r: SetSyncOnMeteredRequest,
) -> RespPayload {
    match context.network_policy.set_sync_on_metered(r.enabled) {
        Ok(state) => to_wire(state),
        Err(e) => RespPayload::Error(format!("could not save the setting: {e}")),
    }
}

pub(super) async fn report_network_cost(
    context: &crate::control_context::ControlContext,
    r: ReportNetworkCostRequest,
) -> RespPayload {
    let cost = match WireCost::try_from(r.cost) {
        Ok(WireCost::Unmetered) => NetworkCost::Unmetered,
        Ok(WireCost::Metered) => NetworkCost::Metered,
        Ok(WireCost::Unknown) | Err(_) => NetworkCost::Unknown,
    };
    to_wire(context.network_policy.report_cost(cost))
}
