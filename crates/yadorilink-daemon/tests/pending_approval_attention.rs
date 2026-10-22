//! Requests waiting on this account's approval, as the coordination plane reports them in the
//! netmap, become a per-folder count and a needs-attention item in `Status`, and clear once the
//! plane stops reporting them. Only a count reaches the daemon: nothing here grants access.

mod support;

use std::time::Duration;

use support::control_socket_client;
use support::fake_coordination::FakeCoordination;
use support::register_with_fake;
use support::topology::{link_eager, new_node, spawn_orchestrator, TopologyNode};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{StatusRequest, StatusResponse};

const GROUP: &str = "pending-approval-group";

async fn status(node: &TopologyNode) -> StatusResponse {
    let handle = control_socket_client::start(node.state.clone()).await;
    let Some(RespPayload::Status(status)) =
        control_socket_client::send(&handle, ReqPayload::Status(StatusRequest {})).await.payload
    else {
        panic!("expected a status response");
    };
    status
}

/// The folder's waiting count and whether the rollup names it, as `Status` reports them now.
async fn waiting(node: &TopologyNode) -> (u32, bool) {
    let status = status(node).await;
    let count =
        status.links.iter().find(|l| l.group_id == GROUP).map_or(0, |l| l.pending_approvals);
    (count, status.attention_reasons.contains(&format!("approval_pending:{GROUP}")))
}

async fn wait_for(node: &TopologyNode, want: (u32, bool)) {
    for _ in 0..200 {
        if waiting(node).await == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never reached {want:?}, last {:?}", waiting(node).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_waiting_on_the_owner_is_counted_and_clears_when_decided() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let node = new_node("pending-approval");
    register_with_fake(&fake, &node.state, &node.device_id, &[GROUP]).await;
    link_eager(&node, GROUP);
    let orchestrator = spawn_orchestrator(fake.addr(), &node);

    // Nothing waiting: no count, no item.
    assert_eq!(waiting(&node).await, (0, false));

    fake.set_pending_approvals(&node.device_id, GROUP, 2);
    wait_for(&node, (2, true)).await;

    // The plane stops reporting it once the owner decided (or the request expired).
    fake.set_pending_approvals(&node.device_id, GROUP, 0);
    wait_for(&node, (0, false)).await;
    orchestrator.shutdown_background();
}
