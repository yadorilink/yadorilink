//! Acceptance tests for peer reconnection: simultaneous multi-peer churn,
//! reconnecting mid-sync, and a daemon generation restarting entirely --
//! plus the ABA-race fix to `NetmapDiffState::channels`'s natural-session-end
//! cleanup (`remove_channel_if_current`).
//!
//! Formerly also covered a `ReconnectCoordinator` global semaphore bounding
//! concurrent mid-handshake supervisors (`peer_orchestrator::NetmapDiffState::
//! reconnect_semaphore`) against one permanently-failing peer starving the
//! rest. That mechanism no longer exists in production -- reconnection is
//! iroh-only now, with no shared handshake-concurrency bottleneck for one
//! bad peer to hog -- so its dedicated scenario
//! (`pathological_peer_does_not_starve_healthy_peers`) was deleted rather
//! than kept green against a mechanism that is no longer there to test.
//!
//! Drives the real production stack exactly like `reconnect_handshake_stress.
//! rs` and `chaos_coordination_unreachable.rs` (real `DaemonState` +
//! `LinkRuntimeController` + `peer_orchestrator::run` against an in-process
//! `FakeCoordination`), star-topology rather than full mesh: a hub device
//! plus N leaves, each leaf sharing a group with the hub ONLY (never with
//! each other) -- keeps connection count and this file's own runtime cost at
//! O(N), not O(N^2), the N-to-1 fan-in shape a real "many peers reconnecting
//! to one already-established machine" event actually has (a laptop waking
//! from sleep, a Wi-Fi roam, a network flap).
//!
//! **What "simultaneous" means here:** `FakeCoordination::revoke` and
//! `register_device` are plain synchronous methods (no `.await` inside their
//! own body) -- calling them back-to-back in a tight loop with no `.await`
//! between iterations cannot be interleaved with anything else on this
//! task, so the whole batch really does land as one atomic moment from the
//! runtime's perspective, not merely "close together". Only the
//! `register_with_fake` re-registration loop (which does real socket setup)
//! is unavoidably sequential; that's fine, since by that point the
//! simultaneous *loss* has already landed and every affected leaf's own
//! supervisor is independently racing its own reconnect regardless of what
//! order this test happens to call `register_with_fake` in.
//!
//! **What "connection loss" means for scenario B:** this file reuses the
//! same revoke-then-reregister technique `reconnect_handshake_stress.rs`
//! itself uses as its network-blip stand-in (see that file's own module doc
//! comment) rather than inventing a lower-level socket-cut simulation --
//! consistent with this codebase's established convention for these
//! full-stack tests, and honestly documented as such here too.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{daemon_status_summary, register_with_fake, wait_until_with_context};
use tokio::task::JoinHandle;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

// --- shared harness (mirrors reconnect_handshake_stress.rs /
// chaos_coordination_unreachable.rs; each full-stack test file in this
// crate keeps its own copy of this scaffolding by established convention,
// not shared-imported) ------------------------------------------------

struct TestDaemon {
    device_id: String,
    state: Arc<DaemonState>,
    _root: tempfile::TempDir,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    // Leaked deliberately: the block store must outlive the test; the
    // process tears the temp dir down on exit.
    let store = Arc::new(SegmentBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon { device_id: device_id.to_string(), state, _root: tempfile::tempdir().unwrap() }
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path, group_id: &str) {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();
}

/// Like [`spawn_orchestrator`], but on a runtime of its own, so shutting
/// that runtime down takes every task the orchestrator spawned with it.
///
/// A plain `JoinHandle::abort` does not: `peer_orchestrator::run` reaches
/// `start_lan_discovery`, which `tokio::spawn`s an announcement reader
/// holding clones of this generation's `DaemonState` and `NetmapDiffState`
/// and parked on `announcements.recv()`. Aborting the outer task leaves
/// that child alive, still holding the old generation -- which a real
/// process restart would obviously have taken down. `support::topology`
/// gives each node its own runtime for exactly this reason.
fn spawn_orchestrator_on_own_runtime(
    coordination_addr: String,
    device_id: String,
    state: Arc<DaemonState>,
) -> tokio::runtime::Runtime {
    let log_device_id = device_id.clone();
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("building a dedicated orchestrator runtime must not fail in tests");
    runtime.spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    });
    runtime
}

fn spawn_orchestrator(
    coordination_addr: String,
    device_id: String,
    state: Arc<DaemonState>,
) -> JoinHandle<()> {
    let log_device_id = device_id.clone();
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id,
    };
    tokio::spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    })
}

/// A hub plus `n_leaves` leaves, star-topology (see this file's own module
/// doc comment). `leaf_groups[i]` is the one group leaf `i` and the hub
/// share; leaves never share a group with each other.
struct StarMesh {
    fake: FakeCoordination,
    hub: TestDaemon,
    leaves: Vec<TestDaemon>,
    leaf_groups: Vec<String>,
    // Kept alive for the mesh's lifetime -- one per hub-side group link;
    // dropping any of these would tear that link down.
    _hub_roots: Vec<tempfile::TempDir>,
}

/// `scenario`-namespaced: the signing-key pin store (`signing_keys.json`,
/// per `peer_orchestrator::signing_key_pins_path`) lives at a
/// SINGLE, process-wide path (`ensure_isolated_config_dir`'s `Once`-bound
/// temp dir), shared by every `#[tokio::test]` function in this one binary
/// -- unlike every other full-stack test file in this crate, which each
/// hold exactly one such test. Two scenarios that both named a device
/// "hub" would pin two DIFFERENT real keypairs to that one device_id, and
/// whichever scenario runs second would see every connection to "hub"
/// silently torn down as a pinned-key mismatch (this was a real, first-try
/// failure in this file's own history: `reconnect_during_active_sync`
/// failing at the simplest possible 1-hub-1-leaf setup, only when run
/// after another scenario in the same process, was the tell). Every
/// scenario below MUST pass its own unique `scenario` string here.
async fn spawn_star_mesh(scenario: &str, n_leaves: usize) -> StarMesh {
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();

    let hub = new_test_daemon(&format!("{scenario}-hub"));
    let leaf_groups: Vec<String> =
        (0..n_leaves).map(|i| format!("{scenario}-star-group-{i}")).collect();
    let hub_group_refs: Vec<&str> = leaf_groups.iter().map(String::as_str).collect();
    register_with_fake(&fake, &hub.state, &hub.device_id, &hub_group_refs).await;

    let mut hub_roots = Vec::with_capacity(n_leaves);
    for group in &leaf_groups {
        let root = tempfile::tempdir().unwrap();
        link(&hub.state, root.path(), group);
        hub_roots.push(root);
    }

    let mut leaves = Vec::with_capacity(n_leaves);
    for (i, group) in leaf_groups.iter().enumerate() {
        let leaf = new_test_daemon(&format!("{scenario}-leaf-{i}"));
        register_with_fake(&fake, &leaf.state, &leaf.device_id, &[group.as_str()]).await;
        link(&leaf.state, leaf._root.path(), group);
        leaves.push(leaf);
    }

    spawn_orchestrator(fake.addr(), hub.device_id.clone(), hub.state.clone());
    for leaf in &leaves {
        spawn_orchestrator(fake.addr(), leaf.device_id.clone(), leaf.state.clone());
    }

    // Must happen after the orchestrators start (the substrate has no
    // address before its stack is serving) and before any caller waits for
    // convergence. See `advertise_substrate`'s own doc comment for why
    // `FakeCoordination` cannot do this itself.
    let mut states: Vec<&Arc<DaemonState>> = vec![&hub.state];
    states.extend(leaves.iter().map(|l| &l.state));
    advertise_substrate(&states).await;

    StarMesh { fake, hub, leaves, leaf_groups, _hub_roots: hub_roots }
}

async fn wait_for_star_connected(mesh: &StarMesh, timeout: Duration, context: &str) {
    wait_until_with_context(
        || {
            mesh.leaves.iter().all(|leaf| {
                mesh.hub.state.peers.session(&leaf.device_id).is_some()
                    && leaf.state.peers.session(&mesh.hub.device_id).is_some()
            })
        },
        timeout,
        || {
            let missing: Vec<_> = mesh
                .leaves
                .iter()
                .filter(|leaf| !mesh.hub.state.peers.has_session(&leaf.device_id))
                .map(|l| l.device_id.clone())
                .collect();
            format!(
                "star mesh did not fully connect ({context}): hub missing sessions with \
                 {missing:?}\nhub: {}",
                daemon_status_summary(&mesh.hub.state)
            )
        },
    )
    .await;
}

async fn wait_for_all_leaves_disconnected(mesh: &StarMesh, timeout: Duration, context: &str) {
    wait_until_with_context(
        || mesh.leaves.iter().all(|leaf| !mesh.hub.state.peers.has_session(&leaf.device_id)),
        timeout,
        || {
            let still_connected: Vec<_> = mesh
                .leaves
                .iter()
                .filter(|leaf| mesh.hub.state.peers.has_session(&leaf.device_id))
                .map(|l| l.device_id.clone())
                .collect();
            format!("not all leaves disconnected simultaneously ({context}): {still_connected:?}")
        },
    )
    .await;
}

// --- scenarios: 10 peers flap / 20 peers lose connection, both at once --

async fn simultaneous_flap_scenario(scenario: &str, n_leaves: usize, timeout: Duration) {
    support::ensure_isolated_config_dir();
    let mesh = spawn_star_mesh(scenario, n_leaves).await;
    wait_for_star_connected(&mesh, timeout, "initial star formation").await;

    // The simultaneous loss itself: see this file's own module doc comment
    // for why this tight, `.await`-free loop is genuinely simultaneous, not
    // merely "close together".
    for (leaf, group) in mesh.leaves.iter().zip(mesh.leaf_groups.iter()) {
        mesh.fake.revoke(&leaf.device_id, group);
    }
    wait_for_all_leaves_disconnected(&mesh, timeout, "post-revoke teardown").await;

    // Lets any packet still in flight from the torn-down generation drain
    // before the next generation's handshake starts on the same shared UDP
    // socket -- mirrors `reconnect_handshake_stress.rs`'s own fix for the
    // exact same class of stale-in-flight-packet flake.
    tokio::time::sleep(Duration::from_millis(300)).await;

    for (leaf, group) in mesh.leaves.iter().zip(mesh.leaf_groups.iter()) {
        register_with_fake(&mesh.fake, &leaf.state, &leaf.device_id, &[group.as_str()]).await;
    }

    wait_for_star_connected(&mesh, timeout, "post-flap reconnect").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ten_peers_flap_simultaneously() {
    simultaneous_flap_scenario("flap10", 10, Duration::from_secs(60)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn twenty_peers_lose_connection_simultaneously() {
    simultaneous_flap_scenario("flap20", 20, Duration::from_secs(90)).await;
}

// --- scenario: reconnect while a transfer is genuinely mid-flight -------

/// Delivers every node's reconciliation-substrate address to every other
/// node -- the same hop `support::topology::advertise_substrate_endpoints`
/// performs, expressed for this file's own `Arc<DaemonState>` fixture.
///
/// This is not optional plumbing. The substrate listens on a DIFFERENT
/// socket with a DIFFERENT ALPN than the legacy peer-session transport, and
/// publishes its address through `AddressDirectory`. Production carries that
/// address over the coordination plane end to end; these fixtures do not,
/// for two reasons that are both on the test side -- see
/// `support::topology::advertise_substrate_endpoints` for both in full.
/// Without this call the star mesh reaches a registered session --
/// which is what `wait_for_star_connected` checks -- while the plane that
/// actually carries DAG changes was never dialable at all.
///
/// Measured before this existed: a leaf would author a change
/// (`heads=1`, file hydrated) and the hub would sit at `heads=0` with no
/// file rows and no obligations for 55+ seconds, with both sides reporting
/// a live session. It reproduced with an 8 MiB payload and with a 1 KiB
/// one, and with the revoke/re-grant churn removed entirely -- so it was
/// never about size or reconnection.
///
/// Delegates rather than keeping a third copy of the distribution loop. The
/// copy that used to live here had the same startup race as the other two:
/// it waited for the SOURCE node to be serving and skipped any target that
/// was not yet, permanently dropping that direction.
async fn advertise_substrate(states: &[&Arc<DaemonState>]) {
    support::advertise_substrate_between(states).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn reconnect_during_active_sync() {
    support::ensure_isolated_config_dir();
    let mesh = spawn_star_mesh("midsync", 1).await;
    wait_for_star_connected(&mesh, Duration::from_secs(60), "initial formation").await;

    let leaf = &mesh.leaves[0];
    let group = &mesh.leaf_groups[0];
    let hub_root = &mesh._hub_roots[0];

    // Large enough that, on loopback, it is very unlikely to have already
    // fully landed by the time the churn below fires immediately after.
    let payload = vec![0xABu8; 8 * 1024 * 1024];
    std::fs::write(leaf._root.path().join("mid-sync.bin"), &payload).unwrap();

    // Fired immediately, with no wait for the transfer to finish -- the
    // whole point is that the revoke/reconnect below genuinely lands while
    // the file is still in flight, not after it already completed.
    mesh.fake.revoke(&leaf.device_id, group);
    wait_until_with_context(
        || !mesh.hub.state.peers.has_session(&leaf.device_id),
        Duration::from_secs(30),
        || "leaf did not disconnect after mid-sync revoke".to_string(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    register_with_fake(&mesh.fake, &leaf.state, &leaf.device_id, &[group.as_str()]).await;

    wait_until_with_context(
        || {
            std::fs::metadata(hub_root.path().join("mid-sync.bin"))
                .map(|m| m.len() as usize == payload.len())
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || {
            format!(
                "file did not fully replicate after reconnect-during-sync churn\nhub: {}\nleaf: {}",
                daemon_status_summary(&mesh.hub.state),
                daemon_status_summary(&leaf.state),
            )
        },
    )
    .await;
    assert_eq!(std::fs::read(hub_root.path().join("mid-sync.bin")).unwrap(), payload);
}

// --- scenario: the daemon generation itself restarts --------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn reconnect_after_daemon_generation_restart() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group = "restart-group";

    // Namespaced device IDs -- see `spawn_star_mesh`'s own doc comment for
    // why: the signing-key pin store (`signing_keys.json`) is shared process-wide across
    // every scenario in this one test binary.
    let hub = new_test_daemon("restart-hub");
    let leaf = new_test_daemon("restart-leaf-0");
    register_with_fake(&fake, &hub.state, &hub.device_id, &[group]).await;
    register_with_fake(&fake, &leaf.state, &leaf.device_id, &[group]).await;
    let hub_root = tempfile::tempdir().unwrap();
    link(&hub.state, hub_root.path(), group);
    link(&leaf.state, leaf._root.path(), group);

    let _hub_handle = spawn_orchestrator(fake.addr(), hub.device_id.clone(), hub.state.clone());
    // On its own runtime so the restart below can take the orchestrator's
    // spawned children down with it, not just its top-level task.
    let leaf_runtime =
        spawn_orchestrator_on_own_runtime(fake.addr(), leaf.device_id.clone(), leaf.state.clone());

    // See `advertise_substrate`'s own doc comment: a registered session
    // (what the wait below checks) is not the same plane this scenario's
    // reconnect actually needs -- unlike `spawn_star_mesh`, this file's own
    // two-device fixture below has no other call site for this.
    advertise_substrate(&[&hub.state, &leaf.state]).await;

    wait_until_with_context(
        || hub.state.peers.session(&leaf.device_id).is_some(),
        Duration::from_secs(60),
        || "initial pair did not connect".to_string(),
    )
    .await;

    // Revoked first, deliberately, so the OLD supervisor's channel tears
    // down through the real, already-tested `teardown_peer` path (not left
    // as a zombie the abort below can't reach: `PeerChannel::connect`'s own
    // background actor task is independent of `run`'s task tree, so
    // aborting the outer orchestrator task alone would NOT reliably stop
    // it). What's actually novel to THIS test is the abort immediately
    // after: it kills `run`'s own top-level task, taking its
    // `NetmapDiffState` -- and with it the `ReconnectCoordinator`'s
    // semaphore -- down with it, exactly as a real supervisor
    // crash/restart would. The freshly spawned orchestrator below gets a
    // brand-new `NetmapDiffState::new()` (a brand-new semaphore, an empty
    // `channels`/`session_tasks` map) and must still reconnect cleanly.
    fake.revoke(&leaf.device_id, group);
    wait_until_with_context(
        || !hub.state.peers.has_session(&leaf.device_id),
        Duration::from_secs(30),
        || "hub never noticed the leaf's pre-restart revoke".to_string(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Requests shutdown and waits up to 5s before continuing. Deliberately
    // not described as a guarantee: Tokio leaks whatever has not stopped by
    // the deadline and `shutdown_timeout` does not report whether that
    // happened.
    //
    // Dropping a runtime blocks, and doing that inside `#[tokio::test]`
    // panics with "Cannot drop a runtime in a context where blocking is not
    // allowed" -- which is why `support::topology` settles for the
    // background form. `spawn_blocking` is the seam that allows the bounded
    // one here.
    tokio::task::spawn_blocking(move || leaf_runtime.shutdown_timeout(Duration::from_secs(5)))
        .await
        .expect("the old leaf generation's runtime must shut down");

    // Restart the leaf DEVICE, not merely its orchestrator task.
    //
    // A real supervisor crash takes the process with it. This is the
    // closest in-process analogue: a new device generation over the same
    // identity, the shape `support::topology::restart_node` uses, with the
    // old generation's orchestrator runtime shut down so its spawned
    // children (notably `start_lan_discovery`'s announcement reader, which
    // holds this generation's state and outlives a bare `JoinHandle::abort`)
    // go with it. It is a fresh-daemon-generation reconnect rather than a
    // literal process restart; see the note at the drop below for what that
    // does and does not cover.
    //
    // The signing-key pin store is NOT part of that gap: `signing_keys.json`
    // lives under `device_config::config_dir()`, so it intentionally survives
    // both this in-process generation restart and a real daemon process
    // restart, which the next process simply reloads. That makes the
    // different-key refusal measured below faithful to production rather
    // than an artefact of testing in-process.
    let leaf_device_id = leaf.device_id.clone();
    // Carried across the restart by hand, because this fixture's
    // `ReplicaCoordinator` is in-memory and a real device instead reloads
    // its persistent identity from the OS keyring when it restarts.
    //
    // This is load-bearing, not tidiness, and both failure modes were
    // measured rather than assumed:
    //
    //   * carrying nothing -> `link` below fails outright with "registered
    //     device restart-leaf-0 has no signing key; refusing index-only
    //     sync";
    //   * carrying a DIFFERENT key -> the leaf never reconnects at all
    //     (`hub: connected_sessions=[]`, the full 60s timeout), because
    //     signing-key pinning (`signing_keys.json`, shared process-wide across
    //     this binary's scenarios) sees a changed key for a known device id
    //     and refuses the connection.
    //
    // That second case is what makes this scenario meaningful: the reconnect
    // below can only succeed for the SAME identity, so the test cannot pass
    // by quietly coming back as a new device. The assertions at the end
    // check that explicitly as well.
    let leaf_signing_key = leaf.state.device_signing_key();
    let pre_restart_leaf_key = leaf_signing_key
        .as_ref()
        .expect("the leaf must already have a change-history identity before the restart")
        .verifying_key()
        .to_bytes();
    LinkRuntimeController::new(leaf.state.clone()).stop(&leaf._root.path().to_string_lossy()).await;
    // What this restart does NOT do, measured rather than assumed: fully
    // release the old `DaemonState`. A `Weak` probe measured 17 strong
    // references still live ten seconds after the orchestrator runtime
    // shutdown, the `LinkRuntimeController::stop` above and this drop. Their
    // complete ownership graph is outside this test's scope -- it was not
    // traced, so no claim is made here about which tasks hold them or
    // whether a fuller teardown is achievable.
    //
    // That is the boundary of this scenario: a fresh daemon generation
    // reconnecting over the same identity, with some of the previous
    // generation still resident. The reconnect being exercised -- new
    // endpoint, new `NetmapDiffState`, same identity -- is genuine
    // regardless, and the dedicated runtime above does remove the
    // orchestrator's own children, which a bare `abort` left running.
    drop(leaf);

    let leaf = new_test_daemon(&leaf_device_id);
    if let Some(key) = leaf_signing_key {
        leaf.state.set_device_signing_key(key);
    }
    link(&leaf.state, leaf._root.path(), group);
    // Registered BEFORE the orchestrator spawns: registering afterwards
    // leaves the fake briefly advertising the pre-restart generation, and
    // the new orchestrator burns its first dial attempt on a stale
    // candidate before any retry.
    register_with_fake(&fake, &leaf.state, &leaf.device_id, &[group]).await;
    let _new_leaf_handle =
        spawn_orchestrator(fake.addr(), leaf.device_id.clone(), leaf.state.clone());

    // The restarted leaf is a genuinely new `DaemonState` with a fresh iroh
    // endpoint -- the pre-restart advertisement above tracked the OLD
    // leaf's address and was dropped along with it, so the hub needs this
    // new generation's address distributed again before it can dial it.
    advertise_substrate(&[&hub.state, &leaf.state]).await;

    wait_until_with_context(
        || hub.state.peers.session(&leaf.device_id).is_some(),
        Duration::from_secs(60),
        || {
            format!(
                "leaf did not reconnect as a fresh daemon generation\nhub: {}",
                daemon_status_summary(&hub.state)
            )
        },
    )
    .await;

    // The reconnect must be the SAME device coming back, not a new one that
    // happens to share a name. Without this, a restart that quietly minted a
    // fresh identity would still satisfy the wait above, and the scenario
    // would be proving something weaker than it claims: any device can
    // connect to the hub, which is not what "reconnect after restart" means.
    assert_eq!(leaf.device_id, leaf_device_id, "the restart must reuse the same device id");
    assert_eq!(
        leaf.state.device_signing_key().map(|k| k.verifying_key().to_bytes()),
        Some(pre_restart_leaf_key),
        "the restarted leaf must carry its pre-restart change-history identity, not a fresh key"
    );
    // Deliberately NOT described as the persistent pin: `peer_signing_key`
    // reads `PeerAuthorityState::peer_netmap_metadata.signing_keys`, the hub's
    // CURRENT netmap metadata for this peer. The durable first-seen pin is a
    // separate thing -- `signing_keys.json`, via `verify_or_pin_peer_key` /
    // `save_signing_key_pins` in `peer_orchestrator` -- and it is never
    // re-pinned on change: a differing key yields `PeerKeyDecision::Mismatch`
    // and "device key changed from pinned value; refusing connection".
    //
    // Which is why the reconnect succeeding at all is the stronger evidence
    // of identity continuity, and is measured separately: a restart carrying
    // a DIFFERENT key never reconnects (the full 60s timeout,
    // `hub: connected_sessions=[]`). This assertion adds that the hub's live
    // view of the leaf still names the pre-restart key rather than having
    // been updated to something else.
    assert_eq!(
        hub.state.authority.peer_signing_key(&leaf.device_id),
        Some(pre_restart_leaf_key),
        "the hub's current netmap metadata for the leaf must still carry the pre-restart key"
    );
}
