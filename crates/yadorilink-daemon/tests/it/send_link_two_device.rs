//! Cross-account one-shot Send at the daemon level: a sender mints a
//! link, the recipient redeems it with their device, the sender's offer goes
//! out under the link's pair-bound grant, and the recipient receives the
//! bytes over Track Send. The two devices share no group. Reuse, expiry,
//! cancel and wrong-device redeem are refused. The fake coordination models
//! the link state machine only; account scoping and hashing are covered by
//! the Worker's own `test/send-links.test.ts`.

use crate::support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{new_node_fast, spawn_orchestrator, TopologyNode};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::daemon_state::DaemonState;

/// Starts Track Send's own background service for `node`, over its own
/// fresh, isolated directory -- never `YADORILINK_CONFIG_DIR` (process-wide,
/// and shared by every node in a multi-node test process; see
/// `send_transfer::run`'s own doc comment for why it takes this as an
/// explicit parameter instead of reading that env var itself).
fn start_send_transfer(node: &TopologyNode) -> tempfile::TempDir {
    let config_dir = tempfile::tempdir().unwrap();
    let state = node.state.clone();
    let dir = config_dir.path().to_path_buf();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::send_transfer::run(state, dir).await;
    });
    config_dir
}

async fn wait_for_send_service(state: &Arc<DaemonState>) {
    wait_until_with_context(
        || state.send_service().is_some(),
        Duration::from_secs(30),
        || "Track Send service never became ready".to_string(),
    )
    .await;
}

/// Pairs two nodes with the coordination fake using an EMPTY group list on
/// both sides and starts Track Send on both. Returns the `FakeCoordination`, the two orchestrator runtimes, and
/// both nodes' Track Send config-dir guards -- all of which must outlive
/// the calling test.
async fn stand_up_two_groupless_devices(
    a_name: &str,
    b_name: &str,
) -> (
    FakeCoordination,
    TopologyNode,
    TopologyNode,
    [tokio::runtime::Runtime; 2],
    [tempfile::TempDir; 2],
) {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;

    let a = new_node_fast(a_name);
    let b = new_node_fast(b_name);
    for node in [&a, &b] {
        // Empty group list: Track Send must work between two same-account
        // devices that share NO folder group at all.
        register_with_fake(&fake, &node.state, &node.device_id, &[]).await;
    }

    let runtimes = [spawn_orchestrator(fake.addr(), &a), spawn_orchestrator(fake.addr(), &b)];

    // Deliberately NOT `fully_connected`: two devices sharing no folder
    // group are never each other's sync peers, so no sync session ever
    // exists between them. That absence is the point: Track Send reaches
    // the receiver on its own ALPN, admitted by the grant the coordination
    // plane issues, with the receiver's iroh address taken from that grant.
    //
    // `wait_for_send_service` below is the readiness signal this scenario
    // needs: `send_transfer::run` publishes a `SendService` only once the
    // daemon's reconciliation stack -- and so its iroh endpoint -- exists.
    // The receiver's substrate address must also be on the plane before a
    // grant can carry it. The harness does not run the daemon's startup, so
    // each node's address report -- the production route by which a
    // device's iroh address reaches the plane -- is started here, and
    // `wait_for_substrate_address` waits for it to land.
    let send_dirs = [start_send_transfer(&a), start_send_transfer(&b)];
    wait_for_send_service(&a.state).await;
    wait_for_send_service(&b.state).await;
    for node in [&a, &b] {
        report_endpoint(&fake, node);
        wait_for_substrate_address(&fake, &node.device_id).await;
    }

    (fake, a, b, runtimes, send_dirs)
}

/// Runs `node`'s real address reporter against the fake: whatever its iroh
/// endpoint publishes (`local_substrate_reachability`) is reported to the
/// plane, exactly as the daemon's startup does in production.
fn report_endpoint(fake: &FakeCoordination, node: &TopologyNode) {
    tokio::spawn(yadorilink_daemon::peer_connectivity_runtime::report_own_address(
        fake.addr(),
        yadorilink_fapi_client::test_support::offline_auth(),
        node.device_id.clone(),
        node.state.peer_connectivity.local_substrate_reachability.clone(),
    ));
}

/// Waits until the coordination fake holds `device_id`'s iroh endpoint
/// address -- what a Track Send grant hands the other side to dial.
async fn wait_for_substrate_address(fake: &FakeCoordination, device_id: &str) {
    wait_until_with_context(
        || fake.substrate_reachability_of(device_id).is_some_and(|(direct, _)| !direct.is_empty()),
        Duration::from_secs(30),
        || format!("{device_id} never published an iroh address"),
    )
    .await;
}

fn shutdown_orchestrators(runtimes: [tokio::runtime::Runtime; 2]) {
    for runtime in runtimes {
        runtime.shutdown_background();
    }
}

use yadorilink_daemon::coordination_client::{
    cancel_send_link, create_send_link, redeem_send_link,
};

fn auth() -> yadorilink_fapi_client::CoordinationAuth {
    yadorilink_fapi_client::test_support::offline_auth()
}

fn write_source(name: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_redeemed_link_lets_the_recipient_receive_the_file() {
    let (fake, a, b, runtimes, _dirs) = stand_up_two_groupless_devices("lk-a", "lk-b").await;
    let link = create_send_link(&fake.addr(), &auth(), &a.device_id, None, &[]).await.unwrap();
    redeem_send_link(&fake.addr(), &auth(), &link.code, &b.device_id).await.unwrap();

    let (_src, path) = write_source("gift.txt", b"across accounts, no folder");
    let sender = a.state.send_service().unwrap();
    let outcome = sender.offer_send(&path, &format!("link:{}", link.link_id)).await.unwrap();

    let receiver = b.state.send_service().unwrap();
    let inbox = receiver.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].sender_device_id, a.device_id);
    let dest = tempfile::tempdir().unwrap();
    receiver.receive_transfer(&outcome.transfer_id, Some(dest.path())).await.unwrap();
    assert_eq!(std::fs::read(dest.path().join("gift.txt")).unwrap(), b"across accounts, no folder");

    // The link was one-use: neither the code nor the link yields a second send.
    assert!(redeem_send_link(&fake.addr(), &auth(), &link.code, &b.device_id).await.is_err());
    assert!(sender.offer_send(&path, &format!("link:{}", link.link_id)).await.is_err());
    shutdown_orchestrators(runtimes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unredeemed_expired_or_cancelled_link_sends_nothing() {
    let (fake, a, b, runtimes, _dirs) = stand_up_two_groupless_devices("lk-a2", "lk-b2").await;
    let (_src, path) = write_source("x.txt", b"x");
    let sender = a.state.send_service().unwrap();
    let target = |id: &str| format!("link:{id}");

    // Not redeemed yet: no recipient to bind a grant to.
    let open = create_send_link(&fake.addr(), &auth(), &a.device_id, None, &[]).await.unwrap();
    assert!(sender.offer_send(&path, &target(&open.link_id)).await.is_err());

    // Expired before redeem.
    let stale = create_send_link(&fake.addr(), &auth(), &a.device_id, None, &[]).await.unwrap();
    fake.expire_send_link(&stale.link_id);
    assert!(redeem_send_link(&fake.addr(), &auth(), &stale.code, &b.device_id).await.is_err());

    // Expired after redeem.
    let late = create_send_link(&fake.addr(), &auth(), &a.device_id, None, &[]).await.unwrap();
    redeem_send_link(&fake.addr(), &auth(), &late.code, &b.device_id).await.unwrap();
    fake.expire_send_link(&late.link_id);
    assert!(sender.offer_send(&path, &target(&late.link_id)).await.is_err());

    // Cancelled before and after redeem.
    let gone = create_send_link(&fake.addr(), &auth(), &a.device_id, None, &[]).await.unwrap();
    cancel_send_link(&fake.addr(), &auth(), &gone.link_id).await.unwrap();
    assert!(redeem_send_link(&fake.addr(), &auth(), &gone.code, &b.device_id).await.is_err());
    let after = create_send_link(&fake.addr(), &auth(), &a.device_id, None, &[]).await.unwrap();
    redeem_send_link(&fake.addr(), &auth(), &after.code, &b.device_id).await.unwrap();
    cancel_send_link(&fake.addr(), &auth(), &after.link_id).await.unwrap();
    assert!(sender.offer_send(&path, &target(&after.link_id)).await.is_err());

    assert!(b.state.send_service().unwrap().list_inbox().unwrap().is_empty());
    shutdown_orchestrators(runtimes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redeeming_onto_the_wrong_device_is_refused_and_leaves_the_link_usable() {
    let (fake, a, b, runtimes, _dirs) = stand_up_two_groupless_devices("lk-a3", "lk-b3").await;
    let link = create_send_link(&fake.addr(), &auth(), &a.device_id, None, &[]).await.unwrap();
    // The sender's own device, and one nobody registered.
    assert!(redeem_send_link(&fake.addr(), &auth(), &link.code, &a.device_id).await.is_err());
    assert!(redeem_send_link(&fake.addr(), &auth(), &link.code, "no-such-device").await.is_err());
    // The right one still works, and the grant goes to it alone.
    redeem_send_link(&fake.addr(), &auth(), &link.code, &b.device_id).await.unwrap();
    let (_src, path) = write_source("y.txt", b"y");
    a.state
        .send_service()
        .unwrap()
        .offer_send(&path, &format!("link:{}", link.link_id))
        .await
        .unwrap();
    assert_eq!(b.state.send_service().unwrap().list_inbox().unwrap().len(), 1);
    shutdown_orchestrators(runtimes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retrying_a_link_send_says_to_create_a_new_link() {
    let (fake, a, b, runtimes, _dirs) = stand_up_two_groupless_devices("lk-a4", "lk-b4").await;
    fake.set_device_account(&a.device_id, "alice");
    fake.set_device_account(&b.device_id, "bob");
    let link = create_send_link(&fake.addr(), &auth(), &a.device_id, None, &[]).await.unwrap();
    redeem_send_link(&fake.addr(), &auth(), &link.code, &b.device_id).await.unwrap();
    let (_src, path) = write_source("z.txt", b"z");
    let sender = a.state.send_service().unwrap();
    let outcome = sender.offer_send(&path, &format!("link:{}", link.link_id)).await.unwrap();
    sender.cancel_transfer(&outcome.transfer_id).unwrap();

    let err = sender.retry_sent_transfer(&outcome.transfer_id).await.unwrap_err().to_string();
    assert!(err.contains("create a new link"), "{err}");
    shutdown_orchestrators(runtimes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_link_carries_several_files_and_a_folder() {
    let (fake, a, b, runtimes, _dirs) = stand_up_two_groupless_devices("lk-a5", "lk-b5").await;
    let link = create_send_link(&fake.addr(), &auth(), &a.device_id, None, &[]).await.unwrap();
    redeem_send_link(&fake.addr(), &auth(), &link.code, &b.device_id).await.unwrap();

    let (_s1, file_a) = write_source("a.txt", b"first");
    // Same basename in another directory: must not overwrite the first.
    let (_s2, file_a2) = write_source("a.txt", b"second one");
    let folder = tempfile::tempdir().unwrap();
    let photos = folder.path().join("photos");
    std::fs::create_dir_all(photos.join("sub")).unwrap();
    std::fs::write(photos.join("x.jpg"), b"xx").unwrap();
    std::fs::write(photos.join("sub").join("y.jpg"), b"yyy").unwrap();

    let sender = a.state.send_service().unwrap();
    // What the link's preview lists is exactly what the later send offers.
    let sources = [file_a, file_a2, photos];
    let mut previewed: Vec<String> = yadorilink_send::manifest::list_offered_files_multi(&sources)
        .unwrap()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let outcome =
        sender.offer_send_many(&sources, &format!("link:{}", link.link_id)).await.unwrap();
    let mut offered = outcome.files_offered.clone();
    previewed.sort();
    offered.sort();
    assert_eq!(previewed, offered);
    assert_eq!(outcome.files_offered.len(), 4);
    assert_eq!(outcome.total_size, 5 + 10 + 2 + 3);

    let receiver = b.state.send_service().unwrap();
    let inbox = receiver.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].files.len(), 4);
    assert_eq!(inbox[0].total_size, 20);
    let dest = tempfile::tempdir().unwrap();
    receiver.receive_transfer(&outcome.transfer_id, Some(dest.path())).await.unwrap();
    let read = |rel: &str| std::fs::read(dest.path().join(rel)).unwrap();
    let mut seen = vec![read("a.txt"), read("a (2).txt")];
    seen.sort();
    assert_eq!(seen, vec![b"first".to_vec(), b"second one".to_vec()]);
    assert_eq!(read("photos/x.jpg"), b"xx");
    assert_eq!(read("photos/sub/y.jpg"), b"yyy");
    shutdown_orchestrators(runtimes);
}
