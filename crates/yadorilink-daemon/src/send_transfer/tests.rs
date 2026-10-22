//! Track Send on the daemon's own iroh endpoint, against its sync peers.
//!
//! Real devices, real endpoints bound through `PeerConnectivityRuntime`, the
//! production `send_transfer::run` wiring. What is pinned: being a sync peer
//! (a pinned device sharing a folder group) does not let a device use Track
//! Send's ALPN; a live grant does; and a device let in for Track Send gets
//! nothing on the sync side -- no sync link, no session, no lane.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use yadorilink_ipc_proto::send::{send_envelope, SendEnvelope, SendManifest, SendManifestAck};
use yadorilink_send::wire::{read_message, write_message};
use yadorilink_sync_substrate::{Lane, PeerAddress};

use crate::daemon_state::{DaemonState, SendGrantPeer};
use crate::sync_adapter::sync_stack::SyncStack;
use crate::sync_adapter::PeerSessionDriver;
use crate::test_support::sync_stack_fixture::{device, pin};

const ALICE: &str = "device-alice";
const BOB: &str = "device-bob";
const CAROL: &str = "device-carol";

/// How long any single network step may take before it counts as "no answer".
const STEP: Duration = Duration::from_secs(10);

struct Device {
    state: Arc<DaemonState>,
    stack: Arc<SyncStack>,
    _dirs: (crate::test_support::sync_stack_fixture::ReleasingDir, tempfile::TempDir),
}

impl Device {
    fn key(&self) -> [u8; 32] {
        *self.stack.peer_id().as_bytes()
    }

    fn address(&self) -> PeerAddress {
        self.stack.local_address()
    }
}

/// A device whose endpoint is bound and driven exactly as a daemon's is, with
/// Track Send started on it through `send_transfer::run`.
async fn start(name: &str, key: u8) -> Device {
    let (state, store_dir) = device(name, key);
    let stack = Arc::new(
        SyncStack::spawn(state.clone(), yadorilink_sync_substrate::NetworkConfig::direct_only())
            .await
            .expect("stack starts"),
    );
    state.install_peer_session_driver(PeerSessionDriver::start(state.clone(), stack.clone()));
    let send_dir = tempfile::tempdir().unwrap();
    {
        let state = state.clone();
        let dir = send_dir.path().to_path_buf();
        tokio::spawn(async move {
            let _ = super::run(state, dir).await;
        });
    }
    let deadline = tokio::time::Instant::now() + STEP;
    while state.send_service().is_none() {
        assert!(tokio::time::Instant::now() < deadline, "{name}: Track Send never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Device { state, stack, _dirs: (store_dir, send_dir) }
}

/// Records `peer` on `local` as a device a live grant names -- what the
/// coordination plane's push (or `local`'s own grant request) records.
fn grant(local: &DaemonState, peer_name: &str, peer: &Device) {
    local.record_send_grant_peer(SendGrantPeer {
        device_id: peer_name.to_string(),
        signing_key: peer.key(),
        reachability: Default::default(),
        grant_id: "grant-under-test".to_string(),
        nonce: "nonce-under-test".to_string(),
        expires_at_unix: i64::MAX,
    });
}

/// Dials `target` on Track Send's ALPN from `from` and presents an offer
/// carrying no grant. `Some(ack)` when the offer reached the Track Send
/// service and was answered; `None` when the connection was refused before
/// any Track Send code saw it.
async fn ungranted_offer(from: &Device, target: &Device) -> Option<SendManifestAck> {
    let attempt = async {
        let connection =
            from.stack.endpoint().node().connect_track_send(&target.address()).await.ok()?;
        let (mut writer, mut reader) = connection.open_stream().await.ok()?;
        write_message(
            &mut writer,
            &SendEnvelope {
                payload: Some(send_envelope::Payload::Manifest(SendManifest {
                    transfer_id: "ungranted".to_string(),
                    files: vec![],
                    total_size: 0,
                    offered_at_unix_nanos: 0,
                })),
                grant_id: String::new(),
                grant_nonce: String::new(),
            },
        )
        .await
        .ok()?;
        writer.finish().ok()?;
        read_message::<_, SendManifestAck>(&mut reader).await.ok()
    };
    tokio::time::timeout(STEP, attempt).await.ok().flatten()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sync_peer_without_a_grant_is_refused_on_the_send_alpn() {
    let alice = start(ALICE, 61).await;
    let bob = start(BOB, 62).await;
    pin(&alice.state, BOB, 62);
    pin(&bob.state, ALICE, 61);
    SyncStack::teach_each_other_for_tests(&alice.stack, &bob.stack);

    // They are sync peers: the sync ALPN admits Bob.
    tokio::time::timeout(STEP, bob.stack.link_to(ALICE))
        .await
        .expect("the sync dial answers")
        .expect("a pinned peer gets a sync link");

    // Sync membership does not open Track Send.
    assert!(
        ungranted_offer(&bob, &alice).await.is_none(),
        "a sync peer with no grant must be refused before any Track Send code runs"
    );
    assert!(alice.state.send_service().unwrap().list_inbox().unwrap().is_empty());

    // A live grant does -- and even then an offer without the grant it
    // names is answered with a rejection, not accepted.
    grant(&alice.state, BOB, &bob);
    let ack = ungranted_offer(&bob, &alice)
        .await
        .expect("a device a live grant names reaches the Track Send service");
    assert!(!ack.accepted, "an admitted connection is still not an authorized offer");
    assert!(alice.state.send_service().unwrap().list_inbox().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_track_send_peer_reaches_nothing_on_the_sync_side() {
    let alice = start(ALICE, 63).await;
    let carol = start(CAROL, 64).await;
    // Carol shares no group with Alice and is not pinned by her: Alice knows
    // Carol only through a Track Send grant.
    grant(&alice.state, CAROL, &carol);

    // The send ALPN admits Carol.
    assert!(ungranted_offer(&carol, &alice).await.is_some(), "the grant admits Carol");

    // Bytes a sync lane would carry, sent on the Track Send connection, are
    // read as a (malformed) Track Send message and go nowhere else.
    let connection = carol
        .stack
        .endpoint()
        .node()
        .connect_track_send(&alice.address())
        .await
        .expect("admitted on the send ALPN");
    let (mut writer, _reader) = connection.open_stream().await.expect("a stream opens");
    writer.write_all(&[Lane::Service.tag(), 0, 0, 0, 0]).await.expect("written");
    writer.finish().expect("finished");

    // The sync ALPN refuses her: the grant is never asked there.
    let sync_attempt = async {
        let link = carol.stack.endpoint().node().connect(alice.stack.peer_id()).await.ok()?;
        let mut lane = link.open_lane(Lane::Service).await.ok()?;
        lane.write_all(b"ping").await.ok()?;
        let mut buf = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut lane, &mut buf).await.ok()?;
        Some(())
    };
    // Addresses for the sync dial: what Carol's directory would need.
    carol.stack.address_directory().record(
        alice.stack.peer_id(),
        alice.address().direct_addrs().copied().collect(),
        Vec::new(),
    );
    assert!(
        matches!(tokio::time::timeout(STEP, sync_attempt).await, Ok(None)),
        "a device let in for Track Send must not get a sync lane"
    );

    assert!(!alice.state.peers.has_session(CAROL), "no sync session for a Track Send peer");
    assert_eq!(
        alice.state.peer_connectivity.reachability(CAROL),
        None,
        "a Track Send connection is not a sync link and is not reported as one"
    );
}

/// Records on `local`'s Track Send store that `peer` accepted an offer from
/// it -- the durable row a receiver's later pull is admitted for.
fn accepted_offer(local: &Device, peer_name: &str, peer: &Device) {
    let store = yadorilink_send::store::SendStore::open(
        local._dirs.1.path().join("send").join("store.sqlite3"),
    )
    .expect("the Track Send store opens");
    store
        .insert_outbound_offered(
            "accepted-offer",
            peer_name,
            &peer.key(),
            "/nowhere",
            &SendManifest::default(),
            0,
        )
        .expect("offer recorded");
    store.mark_outbound_acked("accepted-offer").expect("offer accepted");
}

/// Withdraws `peer_name` from `local`'s netmap the way a netmap update that
/// no longer lists it does: key out of the authority first, then revocation.
fn remove_device(local: &Device, peer_name: &str) {
    let key = local.state.authority.peer_signing_key(peer_name);
    local.state.clear_peer_netmap_metadata(peer_name);
    local.state.peer_connectivity.revoke_device(peer_name, key);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_device_with_an_accepted_offer_is_refused_on_the_send_alpn() {
    let alice = start(ALICE, 65).await;
    let bob = start(BOB, 66).await;
    pin(&alice.state, BOB, 66);
    pin(&bob.state, ALICE, 65);
    accepted_offer(&alice, BOB, &bob);

    // Bob accepted an offer from Alice and is still one of her devices: he
    // may come back to pull, so the send ALPN admits him with no grant.
    assert!(
        ungranted_offer(&bob, &alice).await.is_some(),
        "the receiver of an accepted offer is admitted while it is still an authorized device"
    );

    remove_device(&alice, BOB);

    assert!(
        ungranted_offer(&bob, &alice).await.is_none(),
        "an accepted offer on record must not keep admitting a device that has been removed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_device_closes_its_open_track_send_connection() {
    let alice = start(ALICE, 67).await;
    let bob = start(BOB, 68).await;
    pin(&alice.state, BOB, 68);
    pin(&bob.state, ALICE, 67);
    accepted_offer(&alice, BOB, &bob);

    let connection = tokio::time::timeout(
        STEP,
        bob.stack.endpoint().node().connect_track_send(&alice.address()),
    )
    .await
    .expect("the dial answers")
    .expect("admitted on the send ALPN");
    let (mut writer, mut reader) = connection.open_stream().await.expect("a stream opens");
    // Half a length prefix: Alice's Track Send service has the stream and
    // waits for the rest, so nothing but the connection ending can answer.
    writer.write_all(&[0]).await.expect("written");
    writer.flush().await.expect("flushed");
    tokio::time::sleep(Duration::from_millis(500)).await;

    remove_device(&alice, BOB);

    let read = tokio::time::timeout(STEP, read_message::<_, SendManifestAck>(&mut reader)).await;
    assert!(
        matches!(read, Ok(Err(_))),
        "revoking a device must close the Track Send connection it already had open, got {read:?}"
    );
}

/// A retry meant for one side of a transfer is refused, before anything is done, when the transfer
/// is on the other side; either side or an unknown id is left to the retry itself.
#[test]
fn a_retry_for_the_other_side_of_a_transfer_is_refused_up_front() {
    use super::{check_retry_direction, RetryDirection};
    use yadorilink_send::{SendError, TransferDirection};
    let sent = Some(TransferDirection::Sent);
    let received = Some(TransferDirection::Received);
    assert!(matches!(
        check_retry_direction("t", sent, RetryDirection::Received),
        Err(SendError::NotReceived(_))
    ));
    assert!(matches!(
        check_retry_direction("t", received, RetryDirection::Sent),
        Err(SendError::NotSent(_))
    ));
    for (actual, expected) in [
        (sent, RetryDirection::Sent),
        (received, RetryDirection::Received),
        (sent, RetryDirection::Any),
        (received, RetryDirection::Any),
        (None, RetryDirection::Sent),
    ] {
        assert!(check_retry_direction("t", actual, expected).is_ok());
    }
}
