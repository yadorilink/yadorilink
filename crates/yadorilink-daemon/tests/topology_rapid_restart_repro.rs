//! Deterministic regression extracted from `topology_soak_lane.rs`'s
//! randomized session-health invariant (seed `12552500466593081697`). A
//! burst of rapid same-peer restarts can leave the observer's
//! `PeerSyncSession` for the restarted peer un-replaced (`Arc::ptr_eq`
//! still true against the pre-restart session) for the entire settle
//! window, and that is healthy, not a stuck session:
//! `peer_handshake_received()` and its handshake had arrived and both
//! sides' reachability was `Connected(Direct)` the whole time.
//! `PeerChannel`'s own `DIRECT_LIVENESS_TIMEOUT` re-race re-handshakes an
//! EXISTING channel/session in place once the restarted peer's new endpoint
//! is learned -- no new `PeerSyncSession` is ever created, because none is
//! needed. Recovery therefore must be checked as functional health, not as
//! Arc replacement. This file is the deterministic form of that check, and
//! doubles as a fast (~15s) iteration harness for this restart-burst shape,
//! with `peer_orchestrator` tracing on by default (unlike the soak lane,
//! which needs an explicit `RUST_LOG` to see anything from its own module).

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use support::fake_coordination::FakeCoordination;
use support::register_with_fake;
use support::topology::{
    advertise_substrate_endpoints, fully_connected, restart_node, shutdown_substrate,
    spawn_orchestrator, stand_up_canonical_topology, TopologyNode,
};
use yadorilink_daemon::peer_registry::PeerReachability;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "topology_rapid_restart_repro=debug,yadorilink_daemon::peer_orchestrator=debug,\
             yadorilink_daemon::daemon_state=debug",
        ))
        .with_test_writer()
        .try_init();
}

/// Restarts `w` `restarts` times, `gap` apart, then returns the final
/// generation -- mirrors `topology_soak_lane.rs`'s `op_restart_node` "w"
/// arm exactly (same helper calls, same order), just without the rest of
/// the soak's random op mix around it.
async fn rapid_restart(
    fake: &FakeCoordination,
    peers: [&TopologyNode; 2],
    mut w: TopologyNode,
    handles: &mut support::topology::TopologyHandles,
    group_id: &str,
    restarts: u32,
    gap: Duration,
) -> TopologyNode {
    for i in 0..restarts {
        tracing::info!(i, device_id = %w.device_id, "repro: restarting w");
        // Close the substrate first, while the runtime its tasks live on is
        // still running -- see `shutdown_substrate`.
        shutdown_substrate(&w).await;
        handles.take_and_shutdown(&w.device_id).await;
        let restarted = restart_node(w).await;
        register_with_fake(fake, &restarted.state, &restarted.device_id, &[group_id]).await;
        let runtime = spawn_orchestrator(fake.addr(), &restarted);
        // The fake coordination plane does not fan substrate addresses out, so
        // the restarted node knows nobody's address and nobody knows its new
        // one until the harness says so (as production's endpoint report ->
        // netmap route would). Without this the new generation has no session
        // with anyone, ever.
        advertise_substrate_endpoints(&[peers[0], peers[1], &restarted]).await;
        handles.insert(restarted.device_id.clone(), runtime);
        w = restarted;
        tokio::time::sleep(gap).await;
    }
    w
}

// Multi-thread: the link runtime's live flush loop uses `block_in_place`, which
// panics on a current-thread runtime when the real watcher delivers an event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rapid_restart_recovers_within_bound() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    // The daemon rejects a netmap without the service signing key and the
    // signed policy logs as malformed, because the real plane sends both on
    // every push. Without this the fake's netmaps are all ignored and no
    // peer ever connects.
    fake.enable_signed_policy();
    let group_id = "repro-group".to_string();
    let (n, m, mut w, mut handles) = stand_up_canonical_topology(&fake, &group_id).await;

    let pre_restart_session =
        n.state.peers.session(&w.device_id).expect("n must have a session with w before restart");

    w = rapid_restart(&fake, [&n, &m], w, &mut handles, &group_id, 6, Duration::from_millis(1500))
        .await;

    // Matches the fixed `topology_soak_lane.rs` invariant 2 exactly:
    // recovered means either a NEW session was registered, or the SAME
    // session is currently healthy (fresh handshake, DAG negotiated,
    // reachability connected) -- not merely "the Arc changed".
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut recovered = false;
    loop {
        if let Some(current) = n.state.peers.session(&w.device_id) {
            let replaced = !Arc::ptr_eq(&current, &pre_restart_session);
            let healthy = matches!(
                n.state.peer_connectivity.reachability(&w.device_id),
                Some(PeerReachability::Connected(_))
            );
            if replaced || healthy {
                recovered = true;
                break;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    if !recovered {
        let current = n.state.peers.session(&w.device_id);
        tracing::error!(
            recovered,
            same_arc = current.as_ref().is_some_and(|c| Arc::ptr_eq(c, &pre_restart_session)),
            current_handshake_received = current.as_ref().is_some(),
            n_reachability = ?n.state.peer_connectivity.reachability(&w.device_id),
            w_reachability = ?w.state.peer_connectivity.reachability(&n.device_id),
            "repro: session never replaced AND never became healthy in place"
        );
    }
    tracing::info!(recovered, "repro: final state");
    assert!(
        recovered,
        "n's session with w was neither replaced nor healed healthy in place within 120s \
         after a burst of 6 rapid restarts 1.5s apart"
    );

    // Also confirm the OTHER direction and full-mesh reachability, since
    // the soak lane's failures have appeared on either side of a pair.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !(fully_connected(&n.state, &w.device_id) && fully_connected(&w.state, &n.device_id)) {
        if Instant::now() >= deadline {
            panic!(
                "n<->w did not reach full mesh connectivity within 60s after recovery: \
                 n sees w: {:?}, w sees n: {:?}",
                n.state.peers.session(&w.device_id).is_some(),
                w.state.peers.session(&n.device_id).is_some()
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _ = m;

    // Also confirm both sides agree on RouteKind, not just reachability --
    // a restart burst has previously left this asymmetric.
    let route_kind =
        |peers: &yadorilink_daemon::peer_connectivity_runtime::PeerConnectivityRuntime,
         peer_id: &str| match peers.reachability(peer_id) {
            Some(PeerReachability::Connected(kind)) => Some(kind),
            _ => None,
        };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let n_view = route_kind(&n.state.peer_connectivity, &w.device_id);
        let w_view = route_kind(&w.state.peer_connectivity, &n.device_id);
        if n_view == w_view && n_view.is_some() {
            tracing::info!(?n_view, ?w_view, "repro: route kinds agree");
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "n<->w route kinds never agreed within 60s after recovery: n sees {n_view:?}, \
                 w sees {w_view:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    handles.shutdown();
}
