//! Keep both on a conflict copy another device authored must reach that device. The copy is the
//! author's own head, so the resolving device's delete has to name that foreign head; if the delete
//! is dropped the author keeps its copy for good, the two devices' current states differ for good,
//! and neither can ever report the group's data as safely held elsewhere (`durability_unknown`).

mod support;

use std::time::Duration;

use support::control_socket_client;
use support::fake_coordination::FakeCoordination;
use support::topology::stand_up_topology_two_full_replicas_one_on_demand;
use support::{real_entry_names, wait_until_with_context};
use yadorilink_daemon::durability_service::GroupDurabilityStatus;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::resolve_conflict_response::Result as Outcome;
use yadorilink_ipc_proto::daemonctl::{ConflictResolution, ResolveConflictRequest};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn keep_both_of_a_copy_the_peer_authored_converges_and_custody_settles() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "keep-both-converges-group";
    let (n, m, _w, _handles) =
        stand_up_topology_two_full_replicas_one_on_demand(&fake, group_id).await;

    std::fs::write(n.root.path().join("c.txt"), b"side-n").unwrap();
    std::fs::write(m.root.path().join("c.txt"), b"side-m").unwrap();
    let entries = |d: &support::topology::TopologyNode| real_entry_names(d.root.path());
    wait_until_with_context(
        || entries(&n).len() == 2 && entries(&n) == entries(&m),
        Duration::from_secs(60),
        || format!("{:?} vs {:?}", entries(&n), entries(&m)),
    )
    .await;

    // Whichever side lost authored the copy; resolve on the other one.
    let copy = entries(&n).into_iter().find(|name| name.contains("conflicted copy")).unwrap();
    let author = n.state.replica_coordinator.sqlite().dag_list_versions(group_id, &copy).unwrap()
        [0]
    .origin_device_id
    .clone();
    let (resolver, author_node) =
        if author.as_deref() == Some(n.device_id.as_str()) { (&m, &n) } else { (&n, &m) };
    let socket = control_socket_client::start(resolver.state.clone()).await;
    let resp = control_socket_client::send(
        &socket,
        ReqPayload::ResolveConflict(ResolveConflictRequest {
            copy_path: resolver.root.path().join(&copy).to_string_lossy().into_owned(),
            resolution: ConflictResolution::KeepBoth as i32,
        }),
    )
    .await;
    let Some(RespPayload::ResolveConflict(resp)) = resp.payload else { panic!("{resp:?}") };
    assert!(matches!(resp.result, Some(Outcome::KeptPath(_))), "{resp:?}");

    wait_until_with_context(
        || {
            let a = entries(resolver);
            a == entries(author_node)
                && a.iter().any(|name| name.contains("other version"))
                && !a.iter().any(|name| name.contains("conflicted copy"))
        },
        Duration::from_secs(60),
        || format!("{:?} vs {:?}", entries(resolver), entries(author_node)),
    )
    .await;

    // Same states, so the background check corroborates in both directions.
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            n.state.refresh_custody_confirmation(group_id).await;
            m.state.refresh_custody_confirmation(group_id).await;
            if n.state.group_durability_status(group_id) == GroupDurabilityStatus::Protected
                && m.state.group_durability_status(group_id) == GroupDurabilityStatus::Protected
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("custody never settled after keep-both");
}
