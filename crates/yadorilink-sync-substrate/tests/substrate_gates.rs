//! Step 0 gates for the networking substrate.
//!
//! These pin the transport-level properties the replacement sync protocol is
//! entitled to assume. Each is stated as a property of the substrate, not of a
//! particular timing: nothing here passes because a sleep was long enough.

mod common;

use std::time::Duration;

use common::{round_trip, serve_echo, spawn_node_in};
use tokio::io::AsyncWriteExt;
use yadorilink_sync_substrate::testing::SharedAddressBook;
use yadorilink_sync_substrate::Lane;

/// Gate 1: two peers connect over the Yadori ALPN and exchange traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_connect_over_the_yadori_alpn() {
    let book = SharedAddressBook::new();
    let (alice, mut alice_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;
    let (bob, _bob_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;

    let alice_addr = alice.local_address();
    let alice_task = tokio::spawn(async move {
        let link = alice_inbound.recv().await.expect("inbound link");
        serve_echo(link).await.ok();
    });

    let link = bob.connect(alice_addr.peer()).await.expect("connect");
    assert_eq!(
        link.peer(),
        alice.peer_id(),
        "dialled link must be attributed to the peer actually reached"
    );

    let mut lane = link.open_lane(Lane::Service).await.expect("lane");
    round_trip(&mut lane, b"hello").await;

    alice_task.abort();
}

/// Gate 2: both lane classes carry traffic concurrently on one connection,
/// with several streams open per class.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_lane_classes_carry_traffic_concurrently() {
    let book = SharedAddressBook::new();
    let (alice, mut alice_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;
    let (bob, _bob_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;

    let alice_addr = alice.local_address();
    let alice_task = tokio::spawn(async move {
        let link = alice_inbound.recv().await.expect("inbound link");
        serve_echo(link).await.ok();
    });

    let link = bob.connect(alice_addr.peer()).await.expect("connect");

    // Several streams in each class: a lane is a class of streams, not a
    // single stream.
    let mut opened = Vec::new();
    for _ in 0..3 {
        opened.push((Lane::Service, link.open_lane(Lane::Service).await.expect("service")));
    }
    for _ in 0..3 {
        opened.push((Lane::Block, link.open_lane(Lane::Block).await.expect("block")));
    }

    // Drive them all at once and require every one to complete.
    let mut running = Vec::new();
    for (index, (lane, mut stream)) in opened.into_iter().enumerate() {
        running.push(tokio::spawn(async move {
            let payload = format!("{lane}-stream-{index}").into_bytes();
            round_trip(&mut stream, &payload).await;
        }));
    }
    for task in running {
        task.await.expect("every concurrent lane stream completes");
    }

    alice_task.abort();
}

/// Gate 4: killing the connection mid-session leaves nothing behind. The old
/// link is unusable and a reconnect starts from clean state.
///
/// This is what lets the protocol above discard in-flight session state
/// on disconnect instead of persisting it: correctness is re-derived from the
/// durable sets, never from surviving session state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_killed_connection_leaves_no_session_state_behind() {
    let book = SharedAddressBook::new();
    let (alice, mut alice_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;
    let (bob, _bob_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;

    let alice_addr = alice.local_address();
    let alice_task = tokio::spawn(async move {
        while let Some(link) = alice_inbound.recv().await {
            serve_echo(link);
        }
    });

    let first = bob.connect(alice_addr.peer()).await.expect("connect");
    let mut lane = first.open_lane(Lane::Service).await.expect("lane");
    round_trip(&mut lane, b"before-the-kill").await;

    // Exhaust the block lane's budget, so a budget that survived the kill
    // would be observable as a hang on the reconnected link.
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(first.open_lane(Lane::Block).await.expect("block"));
    }

    first.close();
    assert!(!first.is_open(), "closed link must report itself closed");
    assert!(
        lane.write_all(b"after-the-kill").await.is_err(),
        "a stream on a killed connection must fail rather than silently buffer"
    );
    drop(held);
    drop(lane);

    // Reconnect. Nothing from the previous session may carry over.
    let second = bob.connect(alice_addr.peer()).await.expect("reconnect");
    assert!(second.is_open());

    let mut fresh_blocks = Vec::new();
    for _ in 0..8 {
        fresh_blocks.push(
            tokio::time::timeout(Duration::from_secs(5), second.open_lane(Lane::Block))
                .await
                .expect("block lane budget is fresh on a new link, not inherited")
                .expect("block lane opens"),
        );
    }

    let mut lane = second.open_lane(Lane::Service).await.expect("service lane on the new link");
    round_trip(&mut lane, b"after-the-reconnect").await;

    alice_task.abort();
}

/// Gate 5: restarting the substrate re-registers the Yadori ALPN, under the
/// same transport identity.
///
/// Owning the registration lifecycle is the point. A substrate whose protocol
/// map is rebuilt empty on restart, with no re-registration of a handler
/// registered once from outside, would silently accept connections for an ALPN
/// nobody serves — a lost wake with no error to observe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarting_the_substrate_restores_the_alpn_and_identity() {
    let alice_secret = iroh::SecretKey::generate();
    let alice_id = alice_secret.public();

    // One book across the restart: alice rebinds on a fresh socket and
    // republishes into it, which is what lets bob reach her again without
    // being told anything. A book per node would hide exactly that.
    let book = SharedAddressBook::new();
    let (alice, mut alice_inbound) = spawn_node_in(alice_secret.clone(), &book).await;
    let (bob, _bob_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;

    let first_addr = alice.local_address();
    let first_task = tokio::spawn(async move {
        let link = alice_inbound.recv().await.expect("inbound link");
        serve_echo(link).await.ok();
    });

    let link = bob.connect(first_addr.peer()).await.expect("connect");
    let mut lane = link.open_lane(Lane::Service).await.expect("lane");
    round_trip(&mut lane, b"before-restart").await;

    alice.shutdown().await;
    first_task.abort();
    drop(lane);
    drop(link);

    // Restart under the same key.
    let (alice, mut alice_inbound) = spawn_node_in(alice_secret, &book).await;
    assert_eq!(
        alice.peer_id().as_bytes(),
        alice_id.as_bytes(),
        "transport identity must survive a substrate restart"
    );

    let second_addr = alice.local_address();
    let second_task = tokio::spawn(async move {
        let link = alice_inbound.recv().await.expect("inbound link after restart");
        serve_echo(link).await.ok();
    });

    let link = tokio::time::timeout(Duration::from_secs(10), bob.connect(second_addr.peer()))
        .await
        .expect("reconnect must not hang on an unserved ALPN")
        .expect("the Yadori ALPN is served again after restart");
    let mut lane = link.open_lane(Lane::Service).await.expect("lane");
    round_trip(&mut lane, b"after-restart").await;

    second_task.abort();
}

/// Gate 3: the service lane stays responsive while the block lane is under
/// full load.
///
/// This is the structural guarantee a single shared control stream lacks: there
/// a bulk transfer could sit in front of a small request indefinitely, with no
/// transport error logged. Nothing in that design bounds the delay, so no
/// timeout could substitute for separate lanes.
///
/// Splitting streams removes stream-level head-of-line blocking but leaves
/// connection-level congestion and flow-control credit shared, so the load is
/// every block stream stalled: the receiver never reads one byte, standing in
/// for a receiver whose storage writer is blocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn service_stays_responsive_under_full_block_load() {
    /// Enough to exhaust any plausible stream flow-control window several
    /// times over, so a block stream is genuinely blocked, not merely buffered.
    const STALLED_BYTES: usize = 64 * 1024 * 1024;
    const CHUNK: usize = 64 * 1024;

    /// Generous compared to a healthy loopback round trip, and still four
    /// orders of magnitude below the 784-second starvation being ruled out.
    const DEADLINE: Duration = Duration::from_secs(5);
    const ROUND_TRIPS: usize = 20;

    let book = SharedAddressBook::new();
    let (alice, mut alice_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;
    let (bob, _bob_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;

    let alice_addr = alice.local_address();
    let alice_task = tokio::spawn(async move {
        let link = alice_inbound.recv().await.expect("inbound link");
        common::serve_with_stalled_block_lane(link).await.ok();
    });

    let link = bob.connect(alice_addr.peer()).await.expect("connect");

    // Prove the service lane works before any load exists, so a later
    // failure is attributable to saturation and not to setup.
    let mut service = link.open_lane(Lane::Service).await.expect("service");
    round_trip(&mut service, b"before-load").await;

    // Stall every block stream the budget allows. These tasks are expected to
    // block forever.
    let mut stalled = Vec::new();
    for _ in 0..8 {
        let link = link.clone();
        stalled.push(tokio::spawn(async move {
            let mut block = link.open_lane(Lane::Block).await.expect("block");
            let chunk = vec![0xab_u8; CHUNK];
            let mut written = 0usize;
            while written < STALLED_BYTES {
                if block.write_all(&chunk).await.is_err() {
                    break;
                }
                written += CHUNK;
            }
        }));
    }

    // Give the load time to fill every window it can reach.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        stalled.iter().any(|task| !task.is_finished()),
        "block lane drained instead of stalling; the test is not exercising saturation"
    );

    // The property under test.
    for seq in 1..=ROUND_TRIPS {
        let payload = format!("service-request-{seq}").into_bytes();
        tokio::time::timeout(DEADLINE, round_trip(&mut service, &payload)).await.unwrap_or_else(
            |_| {
                panic!(
                    "service round trip {seq} was starved by block load \
                     (waited {DEADLINE:?})"
                )
            },
        );
    }

    for task in stalled {
        task.abort();
    }
    alice_task.abort();
}

/// Control for the gate above: the same deadline, applied to a round trip that
/// *is* starved, must fail.
///
/// Without this, `service_stays_responsive_under_full_block_load` would
/// pass just as happily if the harness could not observe starvation at all.
/// Here the round trip is issued on the stalled class itself, so it is starved
/// by construction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_starvation_deadline_actually_detects_starvation() {
    const DEADLINE: Duration = Duration::from_secs(3);

    let book = SharedAddressBook::new();
    let (alice, mut alice_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;
    let (bob, _bob_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;

    let alice_addr = alice.local_address();
    let alice_task = tokio::spawn(async move {
        let link = alice_inbound.recv().await.expect("inbound link");
        common::serve_with_stalled_block_lane(link).await.ok();
    });

    let link = bob.connect(alice_addr.peer()).await.expect("connect");
    let mut starved = link.open_lane(Lane::Block).await.expect("block");

    let outcome = tokio::time::timeout(DEADLINE, round_trip(&mut starved, b"never-answered")).await;
    assert!(
        outcome.is_err(),
        "a round trip against a receiver that never reads must not complete; \
         the starvation gate would be vacuous"
    );

    alice_task.abort();
}

/// Gate: the device signing key IS the endpoint identity.
///
/// Nothing else on this plane asserted it. Every other gate here generates a
/// throwaway key, so `spawn_as_device` could have derived an identity any way
/// at all and no test would have noticed -- while the coordination design
/// depends on exactly this: the netmap publishes a device's pinned signing key
/// and NO separate transport identity, and substrate reachability deliberately
/// carries no identity field because the pinned key already determines the
/// endpoint id. A second identity would be an unpinned claim that could
/// disagree with the pinned one.
///
/// So: the id a peer dials is derivable from the netmap alone, with no
/// issuance step and nothing else to distribute.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_devices_signing_key_is_its_endpoint_identity() {
    let device_key = iroh::SecretKey::from_bytes(&[0x5Au8; 32]);
    let expected = device_key.public();

    let book = SharedAddressBook::new();
    let (alice, mut alice_inbound) =
        spawn_node_in(iroh::SecretKey::from_bytes(&device_key.to_bytes()), &book).await;

    assert_eq!(
        alice.peer_id().as_bytes(),
        expected.as_bytes(),
        "the endpoint id must be the device signing key's public half, with nothing derived \
         in between -- the netmap distributes only that key"
    );

    // And it is dialable as that identity: a peer holding nothing but the
    // pinned key reaches this device.
    let (bob, _bob_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;
    let alice_task = tokio::spawn(async move {
        let link = alice_inbound.recv().await.expect("inbound link");
        serve_echo(link).await.ok();
    });

    let link = bob
        .connect(yadorilink_sync_substrate::PeerId::from_bytes(*expected.as_bytes()))
        .await
        .expect("a device is dialable by its signing key alone");
    assert_eq!(
        link.peer().as_bytes(),
        expected.as_bytes(),
        "the reached peer must be the one named, not merely someone at that address"
    );

    let mut lane = link.open_lane(Lane::Service).await.expect("lane");
    round_trip(&mut lane, b"identity").await;
    alice_task.abort();
}

/// A lane's budget is shared out BETWEEN classes, not in arrival order.
///
/// One folder group can want far more of a lane than its budget allows. With a
/// plain FIFO budget, a later request for a DIFFERENT group waits behind every
/// one of them, however small it is and however fair the serving side tries to
/// be about what it does receive. Measured before this gate existed: with 96
/// requests outstanding for one group, the other group's single request
/// reached the serving device's block store at position 97 of 98, while the
/// identical request sent over a second connection landed at position 9.
///
/// The bound this asserts is the one that matters: the second class waits
/// behind at most one turn per OTHER class, not behind the depth of their
/// queues.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_groups_backlog_does_not_put_another_group_behind_all_of_it() {
    /// `LaneLimits::default().block`. Stated here because the point of the
    /// test is what happens once the budget is full, whatever its size.
    const BLOCK_BUDGET: usize = 8;
    const BACKLOG: usize = 24;

    let book = SharedAddressBook::new();
    let (alice, mut alice_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;
    let (bob, _bob_inbound) = spawn_node_in(iroh::SecretKey::generate(), &book).await;

    let alice_addr = alice.local_address();
    let alice_task = tokio::spawn(async move {
        let link = alice_inbound.recv().await.expect("inbound link");
        // Held, not served: this gate is about the DIALLING side's own
        // admission, which is decided before anything reaches the peer.
        std::future::pending::<()>().await;
        drop(link);
    });

    let link = std::sync::Arc::new(bob.connect(alice_addr.peer()).await.expect("connect"));

    // Fill the budget with one group's streams, and keep them.
    let mut held = Vec::new();
    for _ in 0..BLOCK_BUDGET {
        held.push(link.open_lane_for(Lane::Block, "group-a").await.expect("block lane"));
    }

    // A deep backlog for that same group, then one request for another. The
    // ordering here is what makes the assertion mean something: every
    // `group-a` waiter joined the queue BEFORE the `group-b` one.
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<&'static str>();
    let mut waiters = Vec::new();
    for _ in 0..BACKLOG {
        let link = link.clone();
        let done_tx = done_tx.clone();
        waiters.push(tokio::spawn(async move {
            let lane = link.open_lane_for(Lane::Block, "group-a").await.expect("block lane");
            let _ = done_tx.send("group-a");
            std::future::pending::<()>().await;
            drop(lane);
        }));
    }
    // Every `group-a` waiter is queued before `group-b` asks for anything.
    // Without this the test could pass by racing rather than by rotating.
    tokio::time::sleep(Duration::from_millis(200)).await;
    {
        let link = link.clone();
        let done_tx = done_tx.clone();
        waiters.push(tokio::spawn(async move {
            let lane = link.open_lane_for(Lane::Block, "group-b").await.expect("block lane");
            let _ = done_tx.send("group-b");
            std::future::pending::<()>().await;
            drop(lane);
        }));
    }
    drop(done_tx);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        done_rx.try_recv().is_err(),
        "the budget is full, so nothing should have been admitted"
    );

    // Free the budget one slot at a time, and record who gets each one.
    let mut admitted = Vec::new();
    for _ in 0..BLOCK_BUDGET {
        held.pop();
        let class = tokio::time::timeout(Duration::from_secs(5), done_rx.recv())
            .await
            .expect("a freed slot must be handed to someone")
            .expect("the waiters outlive this loop");
        admitted.push(class);
    }

    let position = admitted.iter().position(|class| *class == "group-b");
    assert!(
        position.is_some_and(|position| position < 2),
        "the other group's request waited behind {position:?} admissions when there are only \
         two classes; a fair share is one turn each, not one turn per queued request. Order \
         admitted: {admitted:?}"
    );

    for waiter in waiters {
        waiter.abort();
    }
    alice_task.abort();
}
