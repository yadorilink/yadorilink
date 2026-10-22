//! R2a: `FakeCoordination::set_peer_view_endpoints`/`clear_peer_view_endpoints`
//! -- the per-viewer netmap override that makes an asymmetric relay-forced
//! topology (`M` and `W` mutually unreachable, both reachable from `N`)
//! expressible at all. `update_endpoints` alone cannot: it republishes one
//! device-global list every subscriber sees identically.
//!
//! These tests read the raw netmap JSON a subscriber receives over its
//! WebSocket subscription directly -- the same wire shape a real daemon's
//! `peer_orchestrator` parses -- rather than standing up full `DaemonState`
//! orchestrators, since what is under test here is `FakeCoordination`'s own
//! bookkeeping, not the daemon's reaction to it (that end-to-end path is
//! exercised by the relay-forced topology helper and everything built on
//! it).

mod support;

use futures_util::StreamExt;
use support::fake_coordination::FakeCoordination;
use tokio_tungstenite::tungstenite::Message;

const GROUP: &str = "view-override-group";

fn key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

async fn subscribe_once(addr: &str, device_id: &str) -> serde_json::Value {
    // `FakeCoordination::addr()` returns an `http://`-scheme base (the same
    // string `peer_orchestrator`'s config takes and itself rewrites to
    // `ws://` internally) -- strip that scheme here rather than nesting it
    // inside a second one.
    let host = addr.strip_prefix("http://").unwrap_or(addr);
    let url = format!("ws://{host}/netmap/subscribe?deviceId={device_id}");
    let (mut ws, _response) = tokio_tungstenite::connect_async(url).await.unwrap();
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("subscription never received an initial netmap frame")
        .expect("subscription stream ended before any frame")
        .expect("websocket error reading the initial frame");
    let Message::Text(text) = msg else { panic!("expected a text frame, got {msg:?}") };
    serde_json::from_str(&text).unwrap()
}

/// The `endpoints[].address` list a `netmap` frame reports for `peer_id`,
/// in order.
fn endpoints_for(frame: &serde_json::Value, peer_id: &str) -> Vec<String> {
    frame["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["deviceId"] == peer_id)
        .unwrap_or_else(|| panic!("{peer_id} not present in netmap frame: {frame}"))["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["address"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn a_viewer_specific_override_does_not_leak_to_other_viewers() {
    let fake = FakeCoordination::start().await;
    fake.register_device("device-a", key(1), "real-a:1".into(), &[GROUP]);
    fake.register_device("device-b", key(2), "real-b:1".into(), &[GROUP]);
    fake.register_device("device-c", key(3), "real-c:1".into(), &[GROUP]);

    fake.set_peer_view_endpoints("device-a", "device-c", vec!["127.0.0.1:1".into()]);

    let from_a = subscribe_once(&fake.addr(), "device-a").await;
    let from_b = subscribe_once(&fake.addr(), "device-b").await;

    assert_eq!(
        endpoints_for(&from_a, "device-c"),
        vec!["127.0.0.1:1".to_string()],
        "device-a's own override must apply to device-a's own view of device-c"
    );
    assert_eq!(
        endpoints_for(&from_b, "device-c"),
        vec!["real-c:1".to_string()],
        "device-b was never given an override, so it must see device-c's real endpoint"
    );
}

#[tokio::test]
async fn clearing_an_override_reverts_to_the_real_endpoint() {
    let fake = FakeCoordination::start().await;
    fake.register_device("device-a", key(1), "real-a:1".into(), &[GROUP]);
    fake.register_device("device-c", key(3), "real-c:1".into(), &[GROUP]);

    fake.set_peer_view_endpoints("device-a", "device-c", vec!["127.0.0.1:1".into()]);
    assert_eq!(
        endpoints_for(&subscribe_once(&fake.addr(), "device-a").await, "device-c"),
        vec!["127.0.0.1:1".to_string()]
    );

    fake.clear_peer_view_endpoints("device-a", "device-c");
    assert_eq!(
        endpoints_for(&subscribe_once(&fake.addr(), "device-a").await, "device-c"),
        vec!["real-c:1".to_string()],
        "clearing the override must revert to device-c's globally-advertised endpoint"
    );
}

#[tokio::test]
async fn an_override_survives_the_target_device_re_registering() {
    let fake = FakeCoordination::start().await;
    fake.register_device("device-a", key(1), "real-a:1".into(), &[GROUP]);
    fake.register_device("device-c", key(3), "real-c:1".into(), &[GROUP]);
    fake.set_peer_view_endpoints("device-a", "device-c", vec!["127.0.0.1:1".into()]);

    // A restart re-registering with a fresh real endpoint must not
    // implicitly clear a viewer's override of it -- the exact shape a
    // restart-while-relayed test depends on: the restarted peer's real
    // address must stay invisible to the one viewer the override targets.
    fake.register_device("device-c", key(3), "real-c:2-after-restart".into(), &[GROUP]);

    assert_eq!(
        endpoints_for(&subscribe_once(&fake.addr(), "device-a").await, "device-c"),
        vec!["127.0.0.1:1".to_string()],
        "re-registering the OVERRIDDEN device must not clear a viewer's override of it"
    );
}

#[tokio::test]
async fn removing_a_device_clears_every_override_that_names_it() {
    let fake = FakeCoordination::start().await;
    fake.register_device("device-a", key(1), "real-a:1".into(), &[GROUP]);
    fake.register_device("device-b", key(2), "real-b:1".into(), &[GROUP]);
    fake.register_device("device-c", key(3), "real-c:1".into(), &[GROUP]);
    // One override where device-c is the TARGET, one where it is the
    // VIEWER -- `remove_device` must clear both directions.
    fake.set_peer_view_endpoints("device-a", "device-c", vec!["127.0.0.1:1".into()]);
    fake.set_peer_view_endpoints("device-c", "device-b", vec!["127.0.0.1:1".into()]);

    fake.remove_device("device-c");
    fake.register_device("device-c", key(3), "real-c:2".into(), &[GROUP]);

    assert_eq!(
        endpoints_for(&subscribe_once(&fake.addr(), "device-a").await, "device-c"),
        vec!["real-c:2".to_string()],
        "device-c's re-registration after removal must be seen for real, with no stale override \
         naming it as a target surviving the removal"
    );
    assert_eq!(
        endpoints_for(&subscribe_once(&fake.addr(), "device-c").await, "device-b"),
        vec!["real-b:1".to_string()],
        "no stale override naming the removed device as a VIEWER should survive either"
    );
}
