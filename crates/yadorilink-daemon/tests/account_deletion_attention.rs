//! The deletion state of this device's own account, as the netmap's `self.accountDeletionState`
//! reports it, becomes a needs-attention item in `Status` (`pending` and `urgent` under their own
//! keys) and clears only when the plane says `none` again; a netmap that says nothing leaves it as it was.

mod support;

use std::time::Duration;

use support::control_socket_client;
use support::fake_coordination::FakeCoordination;
use support::register_with_fake;
use support::topology::{new_node, spawn_orchestrator, TopologyNode};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{StatusRequest, StatusResponse};

async fn status(node: &TopologyNode) -> StatusResponse {
    let handle = control_socket_client::start(node.state.clone()).await;
    let Some(RespPayload::Status(status)) =
        control_socket_client::send(&handle, ReqPayload::Status(StatusRequest {})).await.payload
    else {
        panic!("expected a status response");
    };
    status
}

/// The account-deletion reasons of the rollup (other reasons are not what this test is about).
async fn account_deletion_reasons(node: &TopologyNode) -> Vec<String> {
    status(node)
        .await
        .attention_reasons
        .into_iter()
        .filter(|r| r.starts_with("account_deletion_"))
        .collect()
}

async fn wait_for_reasons(node: &TopologyNode, want: &[&str]) {
    for _ in 0..200 {
        let got = account_deletion_reasons(node).await;
        if got == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never reached {want:?}, last {:?}", account_deletion_reasons(node).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scheduled_account_deletion_is_raised_and_cleared_by_the_netmap() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let node = new_node("account-deletion");
    register_with_fake(&fake, &node.state, &node.device_id, &[]).await;
    let orchestrator = spawn_orchestrator(fake.addr(), &node);

    wait_for_reasons(&node, &[]).await;

    fake.set_account_deletion_state(&node.device_id, Some("pending"));
    wait_for_reasons(&node, &["account_deletion_pending"]).await;
    assert_ne!(status(&node).await.overall_state, "healthy");

    fake.set_account_deletion_state(&node.device_id, Some("urgent"));
    wait_for_reasons(&node, &["account_deletion_urgent"]).await;

    // A netmap without `self` says nothing: the warning stays.
    fake.set_account_deletion_state(&node.device_id, None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(account_deletion_reasons(&node).await, ["account_deletion_urgent"]);

    // Cancelled: the next netmap says none explicitly.
    fake.set_account_deletion_state(&node.device_id, Some("none"));
    wait_for_reasons(&node, &[]).await;
    orchestrator.shutdown_background();
}
