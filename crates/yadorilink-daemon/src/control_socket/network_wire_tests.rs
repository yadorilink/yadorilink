//! The metered-network verbs through the control dispatch, and what status says of them.

use std::sync::Arc;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, GetNetworkPolicyRequest, NetworkCost, NetworkPolicy,
    ReportNetworkCostRequest, SetSyncOnMeteredRequest, CONTROL_PROTOCOL_VERSION,
};
use yadorilink_local_storage::SegmentBlockStore;

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

fn context() -> (crate::control_context::ControlContext, tempfile::TempDir) {
    let config = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state =
        DaemonState::new_in(config.path().to_path_buf(), "device-a".into(), sync_state, store);
    (crate::control_context::ControlContext::from_state(state), config)
}

async fn ask(
    context: &crate::control_context::ControlContext,
    payload: ReqPayload,
) -> NetworkPolicy {
    let response = super::handle_request(
        context,
        DaemonControlRequest { payload: Some(payload), protocol_version: CONTROL_PROTOCOL_VERSION },
    )
    .await;
    let Some(RespPayload::NetworkPolicy(answer)) = response.payload else {
        panic!("not a network policy answer: {:?}", response.payload)
    };
    answer.policy.expect("a policy")
}

#[tokio::test]
async fn a_metered_report_pauses_until_the_setting_allows_it_and_status_says_so() {
    let (context, _config) = context();
    let policy = ask(&context, ReqPayload::GetNetworkPolicy(GetNetworkPolicyRequest {})).await;
    assert!(!policy.sync_on_metered && !policy.paused_on_metered);
    assert_eq!(policy.cost, NetworkCost::Unknown as i32);
    let status = crate::status_report::build_status(&context.status_sources).unwrap();
    assert!(!status.network_cost_known, "a fresh engine has not been told the cost");

    let policy = ask(
        &context,
        ReqPayload::ReportNetworkCost(ReportNetworkCostRequest {
            cost: NetworkCost::Metered as i32,
        }),
    )
    .await;
    assert!(policy.paused_on_metered);
    let status = crate::status_report::build_status(&context.status_sources).unwrap();
    assert!(status.paused_on_metered, "status names the pause");
    assert!(status.network_cost_known, "a report makes the cost known");

    let policy =
        ask(&context, ReqPayload::SetSyncOnMetered(SetSyncOnMeteredRequest { enabled: true }))
            .await;
    assert!(policy.sync_on_metered && !policy.paused_on_metered);
    let status = crate::status_report::build_status(&context.status_sources).unwrap();
    assert!(!status.paused_on_metered);
}
