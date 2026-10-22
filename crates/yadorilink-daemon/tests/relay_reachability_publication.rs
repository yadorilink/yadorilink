//! A device's iroh address -- relay URLs included -- reaches the coordination
//! plane, and keeps reaching it.
//!
//! In production nobody hands anyone an address: a device learns its own from
//! its iroh endpoint, publishes it, and a peer off its network can only reach
//! it if what the plane stores is what the endpoint announced.
//!
//! ```text
//!   iroh endpoint          home relay assigned after bind, direct addresses
//!     ↓  address lookup publish
//!   PeerConnectivityRuntime  local_substrate_reachability
//!     ↓  report_own_address
//!   coordination           substrate reachability, stored and forwarded
//! ```
//!
//! The reporter under test is the one the daemon's startup spawns. Its input
//! is driven through `publish_substrate_endpoint`, the call iroh's address
//! lookup makes, so everything after the endpoint is the production path.

mod support;

use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{new_node, TopologyNode};
use support::wait_until_with_context;
use yadorilink_daemon::peer_connectivity_runtime::report_own_address;

/// Starts `node`'s real address reporter against `fake`.
fn spawn_reporter(fake: &FakeCoordination, node: &TopologyNode) -> tokio::task::JoinHandle<()> {
    tokio::spawn(report_own_address(
        fake.addr(),
        yadorilink_fapi_client::test_support::offline_auth(),
        node.device_id.clone(),
        node.state.peer_connectivity.local_substrate_reachability.clone(),
    ))
}

async fn wait_for_stored(
    fake: &FakeCoordination,
    device_id: &str,
    expected: (Vec<String>, Vec<String>),
) {
    wait_until_with_context(
        || fake.substrate_reachability_of(device_id).as_ref() == Some(&expected),
        Duration::from_secs(30),
        || {
            format!(
                "the plane never stored {expected:?} for {device_id}; it holds {:?}",
                fake.substrate_reachability_of(device_id)
            )
        },
    )
    .await;
}

/// What the endpoint announces is what the plane stores, and a later
/// announcement -- the home relay arriving after bind, or moving -- replaces
/// it. A device that advertises only a relay is still reported: for a peer
/// that cannot reach it directly, that relay is its whole reachability.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_endpoints_own_address_reaches_the_plane_and_follows_it() {
    let fake = FakeCoordination::start().await;
    let node = new_node("publishing-node");
    support::register_with_fake(&fake, &node.state, &node.device_id, &[]).await;
    fake.apply_endpoint_reports();

    let reporter = spawn_reporter(&fake, &node);

    // Nothing is announced yet, so nothing is claimed: "not yet known" is not
    // "reachable nowhere".
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fake.endpoint_report_count(),
        0,
        "no report may be sent before the endpoint has published an address"
    );

    let relay = "https://relay.example.invalid./".to_string();
    node.state.peer_connectivity.publish_substrate_endpoint(Vec::new(), vec![relay.clone()]);
    wait_for_stored(&fake, &node.device_id, (Vec::new(), vec![relay.clone()])).await;

    let moved = "https://relay-two.example.invalid./".to_string();
    node.state
        .peer_connectivity
        .publish_substrate_endpoint(vec!["192.0.2.31:41000".parse().unwrap()], vec![moved.clone()]);
    wait_for_stored(&fake, &node.device_id, (vec!["192.0.2.31:41000".to_string()], vec![moved]))
        .await;

    reporter.abort();
}

/// Gate: a report the plane rejects is not a report that is lost.
///
/// The plane is the only way a peer off this network learns where this device
/// answers, and the reporter is event-driven -- it waits for the address to
/// change. An address that never changes again produces no further event, so
/// without the retry a single coordination blip would leave this device
/// permanently unreachable, with nothing anywhere to notice.
///
/// Drives the real reporting loop rather than posting by hand: a test that
/// posted itself would prove nothing about the retry, which lives in that loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_endpoint_report_is_retried_until_it_lands() {
    let fake = FakeCoordination::start().await;
    let node = new_node("retry-node");
    support::register_with_fake(&fake, &node.state, &node.device_id, &[]).await;
    fake.apply_endpoint_reports();

    // The first report is refused. Nothing about the address changes
    // afterwards, so only the retry can make a second one happen.
    fake.fail_next_endpoint_reports(1);

    node.state
        .peer_connectivity
        .publish_substrate_endpoint(vec!["192.0.2.30:41000".parse().unwrap()], Vec::new());
    let reporter = spawn_reporter(&fake, &node);

    wait_until_with_context(
        || fake.substrate_reachability_of(&node.device_id).is_some(),
        Duration::from_secs(30),
        || {
            format!(
                "the refused report was never retried; endpoint POSTs seen: {}",
                fake.endpoint_report_count()
            )
        },
    )
    .await;

    assert!(
        fake.endpoint_report_count() >= 2,
        "the snapshot must have been sent again, not merely sent once and lost"
    );
    reporter.abort();
}
