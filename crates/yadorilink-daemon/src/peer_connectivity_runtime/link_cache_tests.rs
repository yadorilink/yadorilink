//! The per-peer link cache: one device's dial never holds up another's link.
//!
//! A device that is registered but offline makes its dial run to its deadline.
//! Every other device's link, and every block fetch riding on it, must stay
//! unaffected for that whole time.

use std::future::pending;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::daemon_state::DaemonState;
use yadorilink_sync_substrate::{NetworkConfig, PeerLink};

use crate::sync_adapter::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{device, pin};

const ALICE: &str = "device-alice";
const BOB: &str = "device-bob";
const DEAD: &str = "device-dead";

const STEP: Duration = Duration::from_secs(10);

type Dial = Result<PeerLink, &'static str>;

/// What a test needs of the two devices.
struct Fixture {
    bob: Arc<SyncStack>,
    bob_state: Arc<DaemonState>,
    _alice: SyncStack,
    _dirs: (
        crate::test_support::sync_stack_fixture::ReleasingDir,
        crate::test_support::sync_stack_fixture::ReleasingDir,
    ),
}

/// Bob pins a reachable Alice and a registered-but-offline `DEAD`.
async fn bob_with_dead_peer() -> Fixture {
    let (alice, alice_dir) = device(ALICE, 11);
    let (bob_state, bob_dir) = device(BOB, 22);
    pin(&alice, BOB, 22);
    pin(&bob_state, ALICE, 11);
    pin(&bob_state, DEAD, 33);
    let alice_stack =
        SyncStack::spawn(alice, NetworkConfig::direct_only()).await.expect("alice starts");
    let bob_stack = SyncStack::spawn(bob_state.clone(), NetworkConfig::direct_only())
        .await
        .expect("bob starts");
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    Fixture {
        bob: Arc::new(bob_stack),
        bob_state,
        _alice: alice_stack,
        _dirs: (alice_dir, bob_dir),
    }
}

/// A real dial to `peer` through bob's runtime, counted.
fn counted_dial(
    bob: &Arc<SyncStack>,
    dials: &Arc<AtomicUsize>,
) -> impl FnOnce(
    yadorilink_sync_substrate::PeerId,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Dial> + Send>> {
    let (bob, dials) = (bob.clone(), dials.clone());
    move |peer| {
        Box::pin(async move {
            dials.fetch_add(1, Ordering::SeqCst);
            bob.runtime_for_tests().connect(peer).await.map_err(|_| "dial failed")
        })
    }
}

fn spawn_stuck_dial(bob: &Arc<SyncStack>, device: &'static str) -> tokio::task::JoinHandle<()> {
    let bob = bob.clone();
    tokio::spawn(async move {
        let _ = bob.endpoint().link_to(device, |_| pending::<Dial>()).await;
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_that_never_completes_does_not_block_another_devices_link() {
    let fx = bob_with_dead_peer().await;
    let stuck = spawn_stuck_dial(&fx.bob, DEAD);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The healthy peer's lookup answers at once, whatever its own dial does.
    let started = Instant::now();
    let answer = tokio::time::timeout(
        Duration::from_secs(2),
        fx.bob.endpoint().link_to(ALICE, |_| async { Err::<PeerLink, _>("no dial") }),
    )
    .await
    .expect("alice's link is blocked behind the dead peer's dial");
    assert!(answer.is_err());
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "alice's link waited {:?} behind the dead peer's dial",
        started.elapsed()
    );

    // And a real dial to her completes while the other is still in flight.
    tokio::time::timeout(STEP, fx.bob.link_to(ALICE))
        .await
        .expect("alice's dial must not wait for the dead peer's")
        .expect("bob reaches alice");
    assert!(!stuck.is_finished(), "precondition: the dead peer's dial is still in flight");
    stuck.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hundred_concurrent_callers_for_one_device_dial_once() {
    let fx = bob_with_dead_peer().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let mut callers = Vec::new();
    for _ in 0..100 {
        let (bob, dials) = (fx.bob.clone(), dials.clone());
        callers.push(tokio::spawn(async move {
            let dial = counted_dial(&bob, &dials);
            bob.endpoint().link_to(ALICE, dial).await.unwrap().expect("pinned")
        }));
    }
    let mut links = Vec::new();
    for caller in callers {
        links.push(tokio::time::timeout(STEP, caller).await.expect("no caller hangs").unwrap());
    }
    assert_eq!(dials.load(Ordering::SeqCst), 1, "callers for one device must share one dial");
    assert!(links.iter().all(|link| Arc::ptr_eq(link, &links[0])));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_dial_does_not_poison_the_next_call() {
    let fx = bob_with_dead_peer().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let counter = dials.clone();
    let failed = fx
        .bob
        .endpoint()
        .link_to(ALICE, move |_| async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<PeerLink, _>("first dial fails")
        })
        .await;
    assert!(failed.is_err());

    let dial = counted_dial(&fx.bob, &dials);
    tokio::time::timeout(STEP, fx.bob.endpoint().link_to(ALICE, dial))
        .await
        .expect("must not hang")
        .expect("the failure left nothing behind")
        .expect("pinned");
    assert_eq!(dials.load(Ordering::SeqCst), 2, "the next call dials again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_dial_leaves_no_stuck_entry() {
    let fx = bob_with_dead_peer().await;
    let stuck = spawn_stuck_dial(&fx.bob, ALICE);
    tokio::time::sleep(Duration::from_millis(100)).await;
    stuck.abort();
    let _ = stuck.await;
    tokio::time::timeout(STEP, fx.bob.link_to(ALICE))
        .await
        .expect("a cancelled caller must not hold the device's entry")
        .expect("bob reaches alice");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_cached_link_is_reused_without_dialling() {
    let fx = bob_with_dead_peer().await;
    let first = tokio::time::timeout(STEP, fx.bob.link_to(ALICE)).await.unwrap().unwrap();
    let dialled = Arc::new(AtomicUsize::new(0));
    let counter = dialled.clone();
    let again = fx
        .bob
        .endpoint()
        .link_to(ALICE, move |_| async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<PeerLink, _>("must not dial")
        })
        .await
        .unwrap()
        .expect("pinned");
    assert!(Arc::ptr_eq(&first, &again));
    assert_eq!(dialled.load(Ordering::SeqCst), 0);
}

/// A device revoked while its dial is in flight must not come out of that
/// dial as a cached link: the dial finishes, and the link is closed unused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_revoked_during_its_dial_is_not_cached() {
    let fx = bob_with_dead_peer().await;
    let release = Arc::new(tokio::sync::Notify::new());
    let dials = Arc::new(AtomicUsize::new(0));
    let in_flight = {
        let (bob, release, dials) = (fx.bob.clone(), release.clone(), dials.clone());
        tokio::spawn(async move {
            let dial = counted_dial(&bob, &dials);
            bob.endpoint()
                .link_to(ALICE, move |peer| async move {
                    // Connected, but not yet handed back to the cache.
                    let link = dial(peer).await;
                    release.notified().await;
                    link
                })
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The order `teardown_peer` uses: withdraw the key, then sweep.
    let key = fx.bob_state.authority.peer_signing_key(ALICE);
    fx.bob_state.clear_peer_netmap_metadata(ALICE);
    fx.bob_state.peer_connectivity.revoke_device(ALICE, key);
    release.notify_one();

    let outcome = tokio::time::timeout(STEP, in_flight).await.expect("dial finishes").unwrap();
    assert!(
        matches!(outcome, Ok(None)),
        "a revoked device's link must not be handed out, got {:?}",
        outcome.as_ref().map(|link| link.is_some())
    );

    // Pinned again, nothing from the revoked dial is left to be served.
    pin(&fx.bob_state, ALICE, 11);
    let redialled = Arc::new(AtomicUsize::new(0));
    let counter = redialled.clone();
    let _ = fx
        .bob
        .endpoint()
        .link_to(ALICE, move |_| async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<PeerLink, _>("probe")
        })
        .await;
    assert_eq!(redialled.load(Ordering::SeqCst), 1, "no link survived the revocation in the cache");
}

// ---- Accepted links satisfy a pending dial ----

/// A dial that has not finished (and, in production, would run to the QUIC
/// connect deadline) does not hold back a link the authorized peer opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authorized_inbound_link_completes_a_pending_dial() {
    let fx = bob_with_alice_dialling_in().await;
    let pending_dial = {
        let bob = fx.bob.clone();
        tokio::spawn(async move { bob.endpoint().link_to(ALICE, |_| pending::<Dial>()).await })
    };
    // Alice reaches bob; bob accepts and authorizes her connection.
    let _alice_to_bob = tokio::time::timeout(STEP, fx.alice.link_to(BOB))
        .await
        .expect("alice dials")
        .expect("alice reaches bob");
    let link = tokio::time::timeout(STEP, pending_dial)
        .await
        .expect("the accepted link must complete the pending dial")
        .unwrap()
        .expect("no dial error")
        .expect("pinned");
    assert!(link.is_alive());
    assert_eq!(Some(link.peer()), fx.bob.endpoint().peer_id_of(ALICE));
}

/// A link from a device this one does not pin is refused at admission, and
/// one from another pinned device is not the awaited peer's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inbound_link_that_is_not_the_awaited_peers_does_not_satisfy_the_dial() {
    let fx = bob_with_alice_dialling_in().await;
    // Bob waits on DEAD (pinned, never answers). Alice (pinned) and Carol
    // (not pinned by bob) both connect in.
    let waiting = spawn_stuck_dial(&fx.bob, DEAD);
    let (carol_state, _carol_dir) = device("device-carol", 44);
    pin(&carol_state, BOB, 22);
    let carol =
        SyncStack::spawn(carol_state, NetworkConfig::direct_only()).await.expect("carol starts");
    SyncStack::teach_each_other_for_tests(&carol, &fx.bob);

    // Carol: refused (bob does not pin her). The dial's outcome is the sync point.
    let carol_outcome = tokio::time::timeout(STEP, async {
        // Admission may complete after the handshake; the connection is then closed.
        if let Ok(link) = carol.link_to(BOB).await {
            while link.is_alive() {
                tokio::task::yield_now().await;
            }
        }
    })
    .await;
    assert!(carol_outcome.is_ok(), "carol's connection must be refused or closed");

    // Alice: accepted; her link is bob's cached one for ALICE (sync point).
    tokio::time::timeout(STEP, fx.alice.link_to(BOB)).await.unwrap().unwrap();
    tokio::time::timeout(STEP, fx.bob.link_to(ALICE)).await.unwrap().unwrap();

    assert!(!waiting.is_finished(), "neither connection is the awaited peer's");
    waiting.abort();
}

/// A dial that finishes after the peer's own link is current must not replace
/// it, and must not be closed either: the peer may be using that very
/// connection as its own current link. It waits as the standby.
#[tokio::test(flavor = "current_thread")]
async fn a_late_outbound_success_neither_replaces_nor_is_closed() {
    let fx = bob_with_alice_dialling_in().await;
    let runtime = fx.bob.runtime_for_tests().clone();
    let peer = fx.bob.endpoint().peer_id_of(ALICE).unwrap();
    let outbound = runtime.connect(peer).await.expect("dial for the late result");
    let inbound = runtime.connect(peer).await.expect("stands in for the accepted link");
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let gate = Arc::new(tokio::sync::Notify::new());
    let leader = {
        let (bob, gate, outbound) = (fx.bob.clone(), gate.clone(), outbound.clone());
        tokio::spawn(async move {
            bob.endpoint()
                .link_to(ALICE, move |_| async move {
                    let _ = started_tx.send(());
                    gate.notified().await;
                    Ok::<_, &str>(outbound)
                })
                .await
        })
    };
    started_rx.await.expect("the leader is dialling");

    // Both become ready before the leader is polled again.
    gate.notify_one();
    fx.bob.endpoint().links.offer_accepted(ALICE, &inbound);
    let current = leader.await.unwrap().unwrap().expect("pinned");

    assert!(current.is_alive(), "the accepted link stays current");
    assert!(outbound.is_alive(), "the outbound connection is not closed: the peer may use it");
    // The dial finishes on its own task: let it file its link as the standby.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert!(outbound.is_alive(), "the outbound connection is not closed: the peer may use it");
    // It is the next current link when the current one goes.
    inbound.close();
    let next = fx
        .bob
        .endpoint()
        .link_to(ALICE, |_| async { Err::<PeerLink, _>("no dial") })
        .await
        .unwrap()
        .expect("pinned");
    assert!(next.is_alive());
}

/// A dial that fails as the peer's own link comes up has not failed the call.
#[tokio::test(flavor = "current_thread")]
async fn a_late_dial_error_does_not_beat_an_accepted_link() {
    let fx = bob_with_alice_dialling_in().await;
    let runtime = fx.bob.runtime_for_tests().clone();
    let peer = fx.bob.endpoint().peer_id_of(ALICE).unwrap();
    let inbound = runtime.connect(peer).await.expect("stands in for the accepted link");
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let gate = Arc::new(tokio::sync::Notify::new());
    let leader = {
        let (bob, gate) = (fx.bob.clone(), gate.clone());
        tokio::spawn(async move {
            bob.endpoint()
                .link_to(ALICE, move |_| async move {
                    let _ = started_tx.send(());
                    gate.notified().await;
                    Err::<PeerLink, _>("dial timed out")
                })
                .await
        })
    };
    started_rx.await.expect("the leader is dialling");

    gate.notify_one();
    fx.bob.endpoint().links.offer_accepted(ALICE, &inbound);
    let outcome = leader.await.unwrap();

    assert!(
        outcome.as_ref().is_ok_and(|link| link.as_ref().is_some_and(|l| l.is_alive())),
        "the usable accepted link wins over the dial error, got {:?}",
        outcome.as_ref().map(|l| l.is_some())
    );
}

/// Both sides dial each other at once. Whichever connection each side ends up
/// using, neither may close the one the other uses: both links stay up and
/// carry a lane each way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_dials_from_both_sides_leave_both_links_up() {
    for _ in 0..10 {
        let fx = bob_with_alice_dialling_in().await;
        let (to_bob_seen, mut at_bob) = tokio::sync::mpsc::unbounded_channel();
        let (to_alice_seen, mut at_alice) = tokio::sync::mpsc::unbounded_channel();
        for (stack, seen) in [(&fx.bob, to_bob_seen), (&fx.alice, to_alice_seen)] {
            stack.runtime_for_tests().when_lane_stream(Arc::new(move |peer, _group, _lane, _s| {
                let _ = seen.send(peer);
                Box::pin(async {})
            }));
        }
        let (a, b) = tokio::join!(
            tokio::time::timeout(STEP, fx.alice.link_to(BOB)),
            tokio::time::timeout(STEP, fx.bob.link_to(ALICE)),
        );
        let (alice_link, bob_link) = (a.unwrap().unwrap(), b.unwrap().unwrap());
        // A lane each way over the links the two caches handed out.
        for (link, label) in [(&alice_link, "alice"), (&bob_link, "bob")] {
            let mut lane = link.open_lane(yadorilink_sync_substrate::Lane::Service).await.unwrap();
            yadorilink_sync_protocol::session::open_lane(
                &mut lane,
                &yadorilink_sync_protocol::ports::GroupId("g".to_string()),
            )
            .await
            .unwrap_or_else(|e| panic!("{label}'s lane: {e}"));
        }
        tokio::time::timeout(STEP, at_bob.recv()).await.expect("bob serves alice's lane");
        tokio::time::timeout(STEP, at_alice.recv()).await.expect("alice serves bob's lane");
        assert!(alice_link.is_alive() && bob_link.is_alive(), "neither side closed the other's");
    }
}

/// Revocation still closes: an accepted link made current is held, so the
/// sweep reaches it, and a revoked device is not handed a link afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_closes_an_inbound_link_that_became_current() {
    let fx = bob_with_alice_dialling_in().await;
    let _alice_to_bob = tokio::time::timeout(STEP, fx.alice.link_to(BOB)).await.unwrap().unwrap();
    let link = tokio::time::timeout(STEP, fx.bob.link_to(ALICE)).await.unwrap().unwrap();

    let key = fx.bob_state.authority.peer_signing_key(ALICE);
    fx.bob_state.clear_peer_netmap_metadata(ALICE);
    fx.bob_state.peer_connectivity.revoke_device(ALICE, key);

    let closed = async {
        while link.is_alive() {
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(STEP, closed).await.expect("the revoked device's link is closed");
    let after = fx.bob.endpoint().link_to(ALICE, |_| async { Err::<PeerLink, _>("no dial") }).await;
    assert!(matches!(after, Ok(None)), "nothing is handed out for a withdrawn key");
}

/// Bob pins Alice; both learn each other's address, but nothing dials until
/// the test says so.
struct Duo {
    bob: Arc<SyncStack>,
    alice: Arc<SyncStack>,
    bob_state: Arc<DaemonState>,
    _dirs: (
        crate::test_support::sync_stack_fixture::ReleasingDir,
        crate::test_support::sync_stack_fixture::ReleasingDir,
    ),
}

async fn bob_with_alice_dialling_in() -> Duo {
    let (alice_state, alice_dir) = device(ALICE, 11);
    let (bob_state, bob_dir) = device(BOB, 22);
    pin(&alice_state, BOB, 22);
    pin(&bob_state, ALICE, 11);
    pin(&bob_state, DEAD, 33);
    let alice = SyncStack::spawn(alice_state, NetworkConfig::direct_only()).await.unwrap();
    let bob = SyncStack::spawn(bob_state.clone(), NetworkConfig::direct_only()).await.unwrap();
    SyncStack::teach_each_other_for_tests(&alice, &bob);
    Duo { bob: Arc::new(bob), alice: Arc::new(alice), bob_state, _dirs: (alice_dir, bob_dir) }
}

/// A device may open its lanes on the connection the peer dialled (its link
/// cache picked it), so the dialler has to serve the streams that arrive on
/// the connection it dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lane_opened_on_the_inbound_link_is_served_by_the_dialler() {
    let fx = bob_with_alice_dialling_in().await;
    let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
    fx.alice.runtime_for_tests().when_lane_stream(Arc::new(move |peer, group, lane, _stream| {
        let _ = seen_tx.send((peer, group, lane));
        Box::pin(async {})
    }));
    // Alice dials; bob's current link for her is that same connection.
    tokio::time::timeout(STEP, fx.alice.link_to(BOB)).await.unwrap().unwrap();
    let link = tokio::time::timeout(STEP, fx.bob.endpoint().link_to(ALICE, |_| pending::<Dial>()))
        .await
        .unwrap()
        .expect("bob has alice's link")
        .expect("pinned");

    let mut lane = link.open_lane(yadorilink_sync_substrate::Lane::Service).await.unwrap();
    yadorilink_sync_protocol::session::open_lane(
        &mut lane,
        &yadorilink_sync_protocol::ports::GroupId("g".to_string()),
    )
    .await
    .unwrap();

    let (peer, group, kind) =
        tokio::time::timeout(STEP, seen.recv()).await.expect("served").expect("hook alive");
    assert_eq!(peer, fx.bob.peer_id());
    assert_eq!(group.as_str(), "g");
    assert_eq!(kind, yadorilink_sync_substrate::Lane::Service);
}

/// An accepted link that arrives while another is current is not lost: when
/// the current one goes, it is the one the next caller gets, with no dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_accepted_link_behind_a_live_current_one_takes_over_when_it_closes() {
    let fx = bob_with_alice_dialling_in().await;
    let current = tokio::time::timeout(STEP, fx.bob.link_to(ALICE)).await.unwrap().unwrap();
    let peer = fx.bob.endpoint().peer_id_of(ALICE).unwrap();
    let accepted = fx.bob.runtime_for_tests().connect(peer).await.expect("a second connection");
    fx.bob.endpoint().links.offer_accepted(ALICE, &accepted);

    current.close();
    let next = fx
        .bob
        .endpoint()
        .link_to(ALICE, |_| async { Err::<PeerLink, _>("must not dial") })
        .await
        .expect("served from the accepted link, not by a dial")
        .expect("pinned");
    assert!(next.is_alive());
    assert!(!Arc::ptr_eq(&next, &current));
}

/// An accepted link ends the caller's wait, not the dial: while that dial is
/// still running nobody starts a second one beside it.
#[tokio::test(flavor = "current_thread")]
async fn a_detached_dial_still_counts_as_the_dial_in_progress() {
    let fx = bob_with_alice_dialling_in().await;
    let runtime = fx.bob.runtime_for_tests().clone();
    let peer = fx.bob.endpoint().peer_id_of(ALICE).unwrap();
    let inbound = runtime.connect(peer).await.expect("stands in for the accepted link");
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let first = {
        let bob = fx.bob.clone();
        tokio::spawn(async move {
            bob.endpoint()
                .link_to(ALICE, move |_| async move {
                    let _ = started_tx.send(());
                    pending::<Dial>().await
                })
                .await
        })
    };
    started_rx.await.expect("the first dial is running");
    fx.bob.endpoint().links.offer_accepted(ALICE, &inbound);
    first.await.unwrap().unwrap().expect("answered by the accepted link");

    // The accepted link goes; the first dial is still running.
    inbound.close();
    let second_dials = Arc::new(AtomicUsize::new(0));
    let second = {
        let (bob, n) = (fx.bob.clone(), second_dials.clone());
        tokio::spawn(async move {
            bob.endpoint()
                .link_to(ALICE, move |_| async move {
                    n.fetch_add(1, Ordering::SeqCst);
                    pending::<Dial>().await
                })
                .await
        })
    };
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(second_dials.load(Ordering::SeqCst), 0, "a second dial beside the first");
    assert!(!second.is_finished());
    second.abort();
}

/// Three links to one peer: a standby replaced by a newer one is not closed
/// at once -- after simultaneous dials it can be the very connection the peer
/// uses as its current link -- but only after the grace period.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_standby_stays_open_for_the_grace_period_then_closes() {
    let fx = bob_with_alice_dialling_in().await;
    let current = tokio::time::timeout(STEP, fx.bob.link_to(ALICE)).await.unwrap().unwrap();
    let runtime = fx.bob.runtime_for_tests().clone();
    let peer = fx.bob.endpoint().peer_id_of(ALICE).unwrap();
    let first = runtime.connect(peer).await.expect("second connection");
    let second = runtime.connect(peer).await.expect("third connection");
    let links = &fx.bob.endpoint().links;

    links.offer_accepted(ALICE, &first);
    links.offer_accepted(ALICE, &second);
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert!(current.is_alive() && first.is_alive() && second.is_alive());
    assert_eq!(links.retired_count_for_tests(ALICE), 1, "inside the grace period it is kept");

    links.expire_retired_for_tests(ALICE);
    wait_until(|| !first.is_alive()).await;
    assert!(!first.is_alive(), "closed once the grace period is over");
    assert!(current.is_alive() && second.is_alive(), "current and standby are untouched");
    wait_until(|| links.retired_count_for_tests(ALICE) == 0).await;
    assert_eq!(links.retired_count_for_tests(ALICE), 0);
}

/// Yields until `done`, a bounded number of times (no clock involved).
async fn wait_until(mut done: impl FnMut() -> bool) {
    for _ in 0..200_000 {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
    }
}

/// Repeated simultaneous links never pile up: at most MAX_RETIRED replaced
/// links are held at a time, the oldest closed first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaced_standbys_are_bounded() {
    let fx = bob_with_alice_dialling_in().await;
    let current = tokio::time::timeout(STEP, fx.bob.link_to(ALICE)).await.unwrap().unwrap();
    let runtime = fx.bob.runtime_for_tests().clone();
    let peer = fx.bob.endpoint().peer_id_of(ALICE).unwrap();
    let links = &fx.bob.endpoint().links;
    let mut offered = Vec::new();
    for _ in 0..12 {
        offered.push(runtime.connect(peer).await.expect("another connection"));
    }
    for link in &offered {
        links.offer_accepted(ALICE, link);
        assert!(links.retired_count_for_tests(ALICE) <= 4, "retired links are bounded");
    }
    assert!(current.is_alive());
    links.expire_retired_for_tests(ALICE);
    wait_until(|| offered.iter().filter(|l| l.is_alive()).count() <= 1).await;
    let open = offered.iter().filter(|l| l.is_alive()).count();
    assert!(open <= 1, "only the standby is left once the grace period is over, got {open}");
}

/// A retired link that closes first (a revocation, the peer) takes its entry
/// and timer with it at once, without waiting out the grace period; one that
/// outlives the grace period is closed and removed too.
///
/// The peer refuses a fifth inbound connection (`MAX_INBOUND_CONNECTIONS_PER_PEER`)
/// by closing it a moment after the handshake, so the current link plus three
/// more is the most that stay open however slowly the host runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retired_link_leaves_the_cache_when_it_closes_or_its_grace_ends() {
    let fx = bob_with_alice_dialling_in().await;
    let _current = tokio::time::timeout(STEP, fx.bob.link_to(ALICE)).await.unwrap().unwrap();
    let runtime = fx.bob.runtime_for_tests().clone();
    let peer = fx.bob.endpoint().peer_id_of(ALICE).unwrap();
    let links = &fx.bob.endpoint().links;
    let mut made = Vec::new();
    for _ in 0..3 {
        made.push(runtime.connect(peer).await.expect("another connection"));
    }
    assert!(made.iter().all(|link| link.is_alive()), "within the peer's connection cap");
    for link in &made {
        links.offer_accepted(ALICE, link);
    }
    assert_eq!(links.retired_count_for_tests(ALICE), 2);

    // One closes on its own (as a revocation would close it): the grace
    // period has not ended, yet its entry goes.
    made[0].close();
    wait_until(|| links.retired_count_for_tests(ALICE) == 1).await;
    assert_eq!(links.retired_count_for_tests(ALICE), 1, "a closed link leaves at once");

    // The rest are closed and removed when the grace period ends.
    links.expire_retired_for_tests(ALICE);
    wait_until(|| links.retired_count_for_tests(ALICE) == 0).await;
    assert_eq!(links.retired_count_for_tests(ALICE), 0, "no entry outlives its grace period");
}
