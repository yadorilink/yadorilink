//! A session does not wait for this side's own dial when the peer is already
//! connected in, and a keeper replaced across a key change never leaves a
//! native connection authenticated as the old key.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use yadorilink_sync_substrate::{NetworkConfig, PeerId};

use crate::daemon_state::DaemonState;
use crate::sync_adapter::driver::PeerSessionDriver;
use crate::sync_adapter::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{device, pin, ReleasingDir};

const ALICE: &str = "device-alice";
const BOB: &str = "device-bob";

/// A hang guard, not a threshold: the failure mode this guards is the QUIC
/// connect deadline, which is longer.
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

/// Three signing-key bytes ordered by public key, smallest first. The device
/// with the smaller endpoint id is the one that dials native replication.
fn ordered_key_bytes() -> [u8; 3] {
    let mut keys: Vec<(u8, [u8; 32])> = (1u8..=12)
        .map(|b| (b, SigningKey::from_bytes(&[b; 32]).verifying_key().to_bytes()))
        .collect();
    keys.sort_by_key(|(_, public)| *public);
    [keys[0].0, keys[1].0, keys[2].0]
}

fn public(byte: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[byte; 32]).verifying_key().to_bytes()
}

async fn stack(state: &Arc<DaemonState>) -> Arc<SyncStack> {
    Arc::new(SyncStack::spawn(state.clone(), NetworkConfig::direct_only()).await.unwrap())
}

fn teach(from: &SyncStack, to: &SyncStack) {
    let address = to.local_address();
    from.address_directory().record(
        address.peer(),
        address.direct_addrs().copied().collect(),
        address.relay_urls().map(ToString::to_string).collect(),
    );
}

/// Bob's outbound dial to Alice never finishes (it runs to the connect
/// deadline, as one with no usable address does). Alice reaches Bob. Bob's
/// session and native attach must follow Alice's connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_follows_the_peers_inbound_link_while_its_own_dial_is_pending() {
    let [alice_key, bob_key, _] = ordered_key_bytes();
    let (alice, alice_dir) = device(ALICE, alice_key);
    let (bob, bob_dir) = device(BOB, bob_key);
    pin(&alice, BOB, bob_key);
    pin(&bob, ALICE, alice_key);
    let alice_stack = stack(&alice).await;
    let bob_stack = stack(&bob).await;
    // Alice can reach Bob; Bob's dials toward Alice never finish.
    teach(&alice_stack, &bob_stack);
    bob_stack.dials_hang.store(true, std::sync::atomic::Ordering::SeqCst);

    bob.install_peer_session_driver(PeerSessionDriver::start(bob.clone(), bob_stack));
    alice.install_peer_session_driver(PeerSessionDriver::start(alice.clone(), alice_stack));
    assert!(
        within(STEP, || bob.peers.has_session(ALICE) && alice.peers.has_session(BOB)).await,
        "sessions must register from the connection that is up, not after bob's dial gives up"
    );
    assert!(
        within(STEP, || bob.native_replication.is_attached(ALICE)
            && alice.native_replication.is_attached(BOB))
        .await,
        "native replication attaches beside the sessions"
    );
    drop((alice_dir, bob_dir));
}

/// Bob's dial is refused at once (the peer had not admitted him yet), so his
/// keeper is in its reconnect backoff when Alice's connection arrives. The
/// session must follow that connection, not wait the backoff out (first step
/// is 0.75 s at the least, so 600 ms cannot be the backoff elapsing).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_keeper_in_backoff_takes_the_peers_inbound_link() {
    let [alice_key, bob_key, _] = ordered_key_bytes();
    let (alice, alice_dir) = device(ALICE, alice_key);
    let (bob, bob_dir) = device(BOB, bob_key);
    pin(&alice, BOB, bob_key);
    pin(&bob, ALICE, alice_key);
    let alice_stack = stack(&alice).await;
    let bob_stack = stack(&bob).await;
    teach(&alice_stack, &bob_stack);
    bob_stack.dials_fail.store(true, std::sync::atomic::Ordering::SeqCst);

    bob.install_peer_session_driver(PeerSessionDriver::start(bob.clone(), bob_stack));
    // Long enough for the keeper's first (failing) attempt to have happened.
    tokio::time::sleep(Duration::from_millis(200)).await;
    alice.install_peer_session_driver(PeerSessionDriver::start(alice.clone(), alice_stack));
    assert!(
        within(Duration::from_millis(600), || bob.peers.has_session(ALICE)).await,
        "the session must follow the connection the peer opened, not the backoff"
    );
    drop((alice_dir, bob_dir));
}

struct Rotation {
    alice: Arc<DaemonState>,
    alice_stack: Arc<SyncStack>,
    _bob_old: Arc<SyncStack>,
    _bob_new: Arc<SyncStack>,
    old: u8,
    new: u8,
    _dirs: [ReleasingDir; 3],
}

/// Alice (the native dialer) pins BOB under `old`; a second stack holds the
/// key BOB rotates to.
async fn rotation() -> Rotation {
    let [alice_key, old, new] = ordered_key_bytes();
    let (alice, d1) = device(ALICE, alice_key);
    let (bob_old_state, d2) = device(BOB, old);
    let (bob_new_state, d3) = device(BOB, new);
    pin(&alice, BOB, old);
    pin(&bob_old_state, ALICE, alice_key);
    pin(&bob_new_state, ALICE, alice_key);
    let alice_stack = stack(&alice).await;
    let bob_old = stack(&bob_old_state).await;
    let bob_new = stack(&bob_new_state).await;
    teach(&alice_stack, &bob_old);
    teach(&alice_stack, &bob_new);
    Rotation {
        alice,
        alice_stack,
        _bob_old: bob_old,
        _bob_new: bob_new,
        old,
        new,
        _dirs: [d1, d2, d3],
    }
}

/// Across a key replacement the keeper for the device is replaced; the
/// connection that ends up attached is the new key's, and stays so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_key_replacement_only_the_new_keys_native_connection_is_attached() {
    let rot = rotation().await;
    rot.alice.install_peer_session_driver(PeerSessionDriver::start(
        rot.alice.clone(),
        rot.alice_stack.clone(),
    ));
    let (old, new) = (PeerId::from_bytes(public(rot.old)), PeerId::from_bytes(public(rot.new)));
    assert!(
        within(STEP, || rot.alice.native_replication.attached_peer(BOB) == Some(old)).await,
        "precondition: attached under the old key"
    );

    pin(&rot.alice, BOB, rot.new);
    assert!(
        within(STEP, || rot.alice.native_replication.attached_peer(BOB) == Some(new)).await,
        "the replacement keeper attaches the new key's connection"
    );
    // Whatever the replaced keeper was still doing, it cannot put the old
    // key's connection back.
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(rot.alice.native_replication.attached_peer(BOB), Some(new));
    }
}

/// The key a dial was made to is read before the dial. A connection that
/// finishes after the key was replaced is not attached, whichever keeper
/// finished it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_that_finishes_after_the_key_changed_does_not_attach() {
    let rot = rotation().await;
    let old = PeerId::from_bytes(public(rot.old));
    let connection = rot
        .alice_stack
        .endpoint()
        .connect_native_replication(old)
        .await
        .expect("a dial to the old key");

    pin(&rot.alice, BOB, rot.new);
    let outcome = crate::native_replication_runtime::attach_dialed(&rot.alice, BOB, connection);

    assert!(matches!(outcome, crate::native_replication_runtime::DialOutcome::Failed));
    assert!(!rot.alice.native_replication.is_attached(BOB));
}

/// A native connection authenticated as a replaced key must not stand in for
/// the new key's, even when the new keeper registered its session first and
/// the old keeper's release therefore skipped the detach.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attachment_under_the_replaced_key_is_replaced_by_the_new_keys() {
    let rot = rotation().await;
    let old = PeerId::from_bytes(public(rot.old));
    let new = PeerId::from_bytes(public(rot.new));
    let weak = Arc::downgrade(&rot.alice);
    // The new keeper's session stands (no old keeper left to detach anything).
    let _session = super::open_session(&weak, &rot.alice_stack, BOB).expect("a session");
    let connection = rot
        .alice_stack
        .endpoint()
        .connect_native_replication(old)
        .await
        .expect("a dial to the old key");
    assert!(matches!(
        crate::native_replication_runtime::attach_dialed(&rot.alice, BOB, connection),
        crate::native_replication_runtime::DialOutcome::Attached
    ));

    pin(&rot.alice, BOB, rot.new);
    // The production native keeper, as the new session keeper starts it.
    let keeper = tokio::spawn(crate::native_replication_runtime::keep_dialed(
        Arc::downgrade(&rot.alice),
        rot.alice_stack.clone(),
        BOB.to_string(),
    ));
    assert!(
        within(STEP, || rot.alice.native_replication.attached_peer(BOB) == Some(new)).await,
        "the connection left under the old key must not satisfy the new key's keeper"
    );
    keeper.abort();
}

/// The follower itself ends an attachment whose key was replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_follower_detaches_an_attachment_under_a_replaced_key() {
    let rot = rotation().await;
    let old = PeerId::from_bytes(public(rot.old));
    let connection =
        rot.alice_stack.endpoint().connect_native_replication(old).await.expect("old dial");
    crate::native_replication_runtime::attach_dialed(&rot.alice, BOB, connection);
    assert_eq!(rot.alice.native_replication.attached_peer(BOB), Some(old));

    pin(&rot.alice, BOB, rot.new);
    let _keepers = super::keep_peer_sessions(&rot.alice, &rot.alice_stack);
    assert!(
        within(STEP, || rot.alice.native_replication.attached_peer(BOB) != Some(old)).await,
        "nothing stays attached under the replaced key"
    );
}
