//! When a peer session exists: authorized, and reachable over the iroh
//! substrate -- and never because a legacy QUIC channel came up.
//!
//! Two devices, each a `SyncStack` and a `PeerSessionDriver` over real
//! iroh endpoints, exactly the pieces a daemon assembles. No legacy endpoint
//! is bound and no session is registered by hand.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_sync_substrate::NetworkConfig;

use crate::daemon_state::DaemonState;
use crate::sync_adapter::driver::PeerSessionDriver;
use crate::sync_adapter::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{device, pin, GROUP};

const ALICE: &str = "device-alice";
const BOB: &str = "device-bob";

/// Long enough for a dial, a reconnect backoff step and a registration.
const STEP: Duration = Duration::from_secs(20);

async fn within(budget: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    check()
}

struct Pair {
    alice: Arc<DaemonState>,
    bob: Arc<DaemonState>,
    _dirs: (
        crate::test_support::sync_stack_fixture::ReleasingDir,
        crate::test_support::sync_stack_fixture::ReleasingDir,
    ),
}

/// Two devices that pin each other, each with a running driver. When
/// `introduce` is false neither knows where the other answers.
async fn pair(introduce: bool) -> Pair {
    pair_with(introduce, |_, _| {}).await
}

/// [`pair`], with `setup` run on both devices after they pin each other and
/// before either driver starts, so no session can exist while it runs.
async fn pair_with(
    introduce: bool,
    setup: impl FnOnce(&Arc<DaemonState>, &Arc<DaemonState>),
) -> Pair {
    let (alice, alice_dir) = device(ALICE, 11);
    let (bob, bob_dir) = device(BOB, 22);
    pin(&alice, BOB, 22);
    pin(&bob, ALICE, 11);
    setup(&alice, &bob);
    let alice_stack = Arc::new(
        SyncStack::spawn(alice.clone(), NetworkConfig::direct_only())
            .await
            .expect("alice's stack starts"),
    );
    let bob_stack = Arc::new(
        SyncStack::spawn(bob.clone(), NetworkConfig::direct_only())
            .await
            .expect("bob's stack starts"),
    );
    if introduce {
        SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    }
    alice.install_peer_session_driver(PeerSessionDriver::start(alice.clone(), alice_stack));
    bob.install_peer_session_driver(PeerSessionDriver::start(bob.clone(), bob_stack));
    Pair { alice, bob, _dirs: (alice_dir, bob_dir) }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authorized_peer_the_substrate_reaches_gets_a_session_on_both_sides() {
    let pair = pair(true).await;

    assert!(
        within(STEP, || pair.alice.peers.has_session(BOB) && pair.bob.peers.has_session(ALICE))
            .await,
        "each device must hold a session for the other once their endpoints connect"
    );
    let session = pair.alice.peers.session(BOB).expect("alice's session for bob");
    assert!(session.shares_group(GROUP), "the session serves the group the netmap authorizes");
    assert!(
        !pair.alice.peers.convergence_for_group(GROUP).is_empty(),
        "the session is a content source for the group, with its convergence executor beside it"
    );
    assert_eq!(
        pair.alice.peer_connectivity.connected_peer_count(),
        1,
        "the connection the session lives on keeps the peer reading connected"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_the_substrate_cannot_reach_gets_no_session_until_it_can() {
    let pair = pair(false).await;

    assert!(
        !within(Duration::from_secs(3), || pair.alice.peers.has_session(BOB)).await,
        "authorization alone is not a session: with nowhere to dial, there is none"
    );

    let alice_stack = pair.alice.peer_session_driver().unwrap().stack().clone();
    let bob_stack = pair.bob.peer_session_driver().unwrap().stack().clone();
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    assert!(
        within(Duration::from_secs(60), || pair.alice.peers.has_session(BOB)).await,
        "once the peer can be reached, the session follows without anything else happening"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_the_netmap_withdraws_loses_its_session() {
    let pair = pair(true).await;
    assert!(within(STEP, || pair.alice.peers.has_session(BOB)).await, "precondition");

    let key = pair.alice.authority.peer_signing_key(BOB);
    pair.alice.clear_peer_netmap_metadata(BOB);
    pair.alice.peer_connectivity.revoke_device(BOB, key);

    assert!(
        within(STEP, || !pair.alice.peers.has_session(BOB)).await,
        "a device the netmap no longer pins must not keep a session"
    );
    assert!(
        !within(Duration::from_secs(3), || pair.alice.peers.has_session(BOB)).await,
        "and must not get one back while it stays withdrawn"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_ends_with_its_connection_and_with_its_driver() {
    let pair = pair(true).await;
    assert!(
        within(STEP, || pair.alice.peers.has_session(BOB) && pair.bob.peers.has_session(ALICE))
            .await,
        "precondition"
    );

    // Bob stops answering: his endpoint closes. Alice's connection to him
    // ends, and her session with it.
    let bob_driver = pair.bob.take_peer_session_driver().expect("bob's driver");
    bob_driver.stack().shutdown().await;
    drop(bob_driver);

    assert!(
        within(STEP, || !pair.alice.peers.has_session(BOB)).await,
        "a session must not outlive the only connection it had to its peer"
    );
    assert!(
        within(STEP, || !pair.bob.peers.has_session(ALICE)).await,
        "and a device whose driver is gone keeps no session over the endpoint it had"
    );
}

/// A keeper that connects while another session for its peer is still
/// registered must take over once that session goes, not wait for its
/// connection to change. A replaced keeper removes its session only as it
/// stops, which can be after its replacement has already looked; without
/// this the peer stays connected with no session at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_keeper_that_finds_another_session_standing_takes_over_once_it_goes() {
    let pair = pair(true).await;
    assert!(
        within(STEP, || pair.alice.peers.has_session(BOB) && pair.bob.peers.has_session(ALICE))
            .await,
        "precondition"
    );
    let alice_stack = pair.alice.peer_session_driver().unwrap().stack().clone();

    // Stand a session the keeper did not register in its place -- what a
    // replaced keeper's session looks like to its successor.
    let kept = pair.alice.peers.session(BOB).unwrap();
    assert!(pair.alice.peers.remove_if_current(BOB, &kept));
    let standing = super::open_session(&Arc::downgrade(&pair.alice), &alice_stack, BOB)
        .expect("a session can be opened in the keeper's place");

    // End the connection: the keeper reconnects, and finds that session.
    alice_stack.link_to(BOB).await.expect("the live link").close();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        pair.alice.peers.session(BOB).is_some_and(|current| Arc::ptr_eq(&current, &standing)),
        "precondition: the standing session is still the registered one"
    );

    assert!(pair.alice.peers.remove_if_current(BOB, &standing));
    assert!(
        within(STEP, || pair
            .alice
            .peers
            .session(BOB)
            .is_some_and(|current| !Arc::ptr_eq(&current, &standing)))
        .await,
        "once the standing session goes, the keeper must open its own over the live connection"
    );
}

/// Reachability is read from live iroh connections only, so a peer this
/// device is not currently exchanging anything with reads connected only if
/// some connection to it stays up. The keeper's is that connection: a
/// pinned, authorized peer with nothing in flight reads connected, and a
/// confirmation it gave stays "available now", for as long as it is up --
/// not only while a reconciliation pass happens to hold a dial open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_quiet_authorized_peer_stays_connected_and_available_while_its_keeper_holds_a_connection()
{
    use crate::background_custody::BackgroundCustodyEvidence;
    use crate::peer_registry::PeerReachability;
    use crate::route::RouteKind;

    let pair = pair(true).await;
    assert!(within(STEP, || pair.alice.peers.has_session(BOB)).await, "precondition");
    let digest = pair
        .alice
        .local_root_set_summary(GROUP)
        .expect("the group's current root set can be summarised")
        .current_digest;
    pair.alice.publish_background_custody(
        GROUP,
        BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some(BOB.into()),
            current_digest: digest,
            roots_digest_matched: true,
        },
        pair.alice.authority.membership_generation(),
        0,
    );

    // Nothing is written on either side, so nothing else dials. Sampled over
    // several reconnect backoffs, well past any one pass's dial.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    while tokio::time::Instant::now() < deadline {
        assert_eq!(
            pair.alice.peer_connectivity.reachability(BOB),
            Some(PeerReachability::Connected(RouteKind::Direct)),
            "a quiet authorized peer must read connected while its keeper's connection is up"
        );
        assert_eq!(pair.alice.peer_connectivity.connected_peer_count(), 1);
        assert!(
            pair.alice.fetch_available_via_confirmed_peer(GROUP),
            "the peer that confirmed the group must count as available now"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Custody confirmation runs when the peer session opens, not at
/// the next 90 s sweep (no sweep task exists in this fixture), and fetch
/// availability follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn opening_a_peer_session_triggers_custody_confirmation_promptly() {
    let pair = pair(true).await;
    assert!(within(STEP, || pair.alice.peers.has_session(BOB)).await, "precondition");
    assert!(
        within(STEP, || pair.alice.durability().has_ever_been_custody_swept(GROUP)).await,
        "a session opening must run a custody confirmation without waiting for the sweep"
    );
    assert!(
        within(STEP, || pair.alice.fetch_available_via_confirmed_peer(GROUP)).await,
        "fetch availability flips as soon as the refresh publishes"
    );
}

/// A burst of session events leaves at most one pending refresh per group.
#[tokio::test(flavor = "current_thread")]
async fn a_burst_of_session_events_coalesces_to_one_refresh_per_group() {
    let (alice, _dir) = device(ALICE, 11);
    let groups = vec![GROUP.to_string()];
    assert_eq!(alice.request_custody_refresh(&groups), 1);
    for _ in 0..10 {
        assert_eq!(alice.request_custody_refresh(&groups), 0, "already pending");
    }
    // Let the single task start; a later event schedules a fresh one.
    while !alice.durability().has_ever_been_custody_swept(GROUP) {
        tokio::task::yield_now().await;
    }
    assert_eq!(alice.request_custody_refresh(&groups), 1);
}

// Integration: a real, content-bearing group and a real peer that
// answers the custody question. The 90 s sweep task does not exist in this
// fixture and no clock is advanced, so anything that becomes available did so
// because the session opening ran the refresh.

const FILE: &str = "only.bin";

fn record(path: &str, size: u64) -> yadorilink_replica_domain::file::FileRecord {
    use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
    FileRecord {
        path: path.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: vec![7; 32], offset: 0, size: size as u32 }],
        deleted: false,
    }
}

/// Alice (the asker, an on-demand view: row indexed, bytes not fetched) and
/// Bob (holds the file) index the same version; Bob's copy is hydrated.
fn seed_shared_file(
    alice: &Arc<DaemonState>,
    bob: &Arc<DaemonState>,
) -> (tempfile::TempDir, tempfile::TempDir) {
    use yadorilink_root_authority::root_commit::RootCommitPermit;
    let alice_root = tempfile::tempdir().unwrap();
    let bob_root = tempfile::tempdir().unwrap();
    let alice_path = crate::test_support::sync_stack_fixture::link_folder(alice, alice_root.path());
    let bob_path = crate::test_support::sync_stack_fixture::link_folder(bob, bob_root.path());
    let permit = RootCommitPermit::for_tests();
    let rec = record(FILE, 5);
    alice.replica_coordinator.file_index_repository().upsert_file(GROUP, &rec, &permit).unwrap();
    bob.replica_coordinator.file_index_repository().upsert_file(GROUP, &rec, &permit).unwrap();
    let on_disk = bob_path.join(FILE);
    std::fs::write(&on_disk, b"hello").unwrap();
    crate::test_support::seed_prior_cycle_proof(
        &bob.replica_coordinator,
        GROUP,
        FILE,
        &on_disk,
        &permit,
    );
    let _ = alice_path;
    (alice_root, bob_root)
}

fn fetch_availability(state: &Arc<DaemonState>) -> crate::queries::link_status::FetchAvailability {
    use crate::adapters::query::link_status::DaemonLinkStatusReader;
    use crate::queries::link_status::LinkStatusReadPort;
    let views = DaemonLinkStatusReader::new(state.clone()).list_links().unwrap();
    views.iter().find(|v| v.group_id == GROUP).expect("the linked group").fetch_availability
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_replica_writer_peer_makes_content_fetchable_as_soon_as_its_session_opens() {
    let mut roots = None;
    let pair = pair_with(true, |alice, bob| {
        roots = Some(seed_shared_file(alice, bob));
        alice.authority.set_peer_group_full_replica(BOB, GROUP, true);
        bob.authority.set_peer_group_full_replica(ALICE, GROUP, true);
    })
    .await;
    let started = std::time::Instant::now();
    assert!(
        within(Duration::from_secs(10), || pair.alice.fetch_available_via_confirmed_peer(GROUP))
            .await,
        "custody confirmation must run when the session opens, not at the 90 s sweep"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(
        fetch_availability(&pair.alice),
        crate::queries::link_status::FetchAvailability::AvailableNow,
        "the status a user sees clears 'fetch not confirmed'"
    );
    drop(roots);
}

/// The pinned regression: a peer that is authorized and connected but not a
/// full replica cannot make content fetchable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_is_not_a_full_replica_never_makes_content_fetchable() {
    let mut roots = None;
    let pair = pair_with(true, |alice, bob| {
        roots = Some(seed_shared_file(alice, bob));
    })
    .await;
    assert!(within(STEP, || pair.alice.peers.has_session(BOB)).await, "precondition");
    assert!(
        within(STEP, || pair.alice.durability().has_ever_been_custody_swept(GROUP)).await,
        "the session event still ran a refresh (a negative one)"
    );
    assert!(!pair.alice.fetch_available_via_confirmed_peer(GROUP));
    assert_eq!(
        fetch_availability(&pair.alice),
        crate::queries::link_status::FetchAvailability::UnavailableNow
    );
    drop(roots);
}

/// Restart: the new process has no confirmation and no session. 'Fetch not confirmed
/// now' must clear within seconds of the session coming back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cannot_fetch_now_clears_within_seconds_of_the_session_returning_after_a_restart() {
    let mut roots = None;
    let pair = pair_with(true, |alice, bob| {
        roots = Some(seed_shared_file(alice, bob));
        alice.authority.set_peer_group_full_replica(BOB, GROUP, true);
        bob.authority.set_peer_group_full_replica(ALICE, GROUP, true);
    })
    .await;
    assert!(
        within(Duration::from_secs(60), || pair.alice.fetch_available_via_confirmed_peer(GROUP))
            .await,
        "precondition"
    );

    // Alice "restarts": her confirmation is gone and her session with Bob
    // has to be built again. Read the status in the same step as the clear:
    // once the session is removed the driver may rebuild it and confirm again
    // at any moment, so no later read can tell "restarted" from "recovered".
    let old = pair.alice.peers.session(BOB).expect("session");
    pair.alice.durability().clear_custody_confirmation(GROUP);
    assert_eq!(
        fetch_availability(&pair.alice),
        crate::queries::link_status::FetchAvailability::UnavailableNow,
        "right after the restart, content cannot be fetched"
    );
    assert!(pair.alice.peers.remove_if_current(BOB, &old));
    let alice_stack = pair.alice.peer_session_driver().unwrap().stack().clone();
    alice_stack.link_to(BOB).await.expect("the live link").close();
    assert!(
        within(Duration::from_secs(60), || {
            fetch_availability(&pair.alice)
                == crate::queries::link_status::FetchAvailability::AvailableNow
        })
        .await,
        "'fetch not confirmed' must clear without waiting for the 90 s sweep"
    );
    drop(roots);
}
