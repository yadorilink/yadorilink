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
                    ..Default::default()
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
    store.mark_outbound_acked("accepted-offer", 0).expect("offer accepted");
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

#[test]
fn only_a_link_prefixed_target_names_a_send_link() {
    use super::link_id_of;
    assert_eq!(link_id_of("link:abc-123"), Some("abc-123"));
    assert_eq!(link_id_of("link:"), None);
    assert_eq!(link_id_of("device-bob"), None);
    assert_eq!(link_id_of("LINK:abc"), None);
}

#[test]
fn a_sender_proceeds_only_on_a_redeemed_link() {
    use super::{link_readiness, LinkReadiness};
    assert_eq!(link_readiness("redeemed"), LinkReadiness::Ready);
    assert_eq!(link_readiness("open"), LinkReadiness::Waiting);
    // Reuse, cancel, expiry and anything unknown stop the send before a grant is asked for,
    // each with its own typed code.
    use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode as Code;
    for (state, code) in [
        ("granted", Code::SendLinkAlreadyUsed),
        ("cancelled", Code::SendLinkCancelled),
        ("expired", Code::SendLinkExpired),
        ("something-new", Code::SendLinkInvalid),
    ] {
        assert!(
            matches!(link_readiness(state), LinkReadiness::Refused(c, _) if c == code),
            "{state}"
        );
    }
}

#[test]
fn a_links_state_follows_the_service_and_its_transfer() {
    use super::link_state;
    use yadorilink_ipc_proto::daemonctl::SendLinkState as S;
    assert_eq!(link_state("open", None, false), S::Waiting);
    assert_eq!(link_state("redeemed", None, false), S::Redeemed);
    assert_eq!(link_state("cancelled", None, false), S::Cancelled);
    assert_eq!(link_state("expired", None, false), S::Expired);
    assert_eq!(link_state("something-new", None, false), S::Unspecified);
    // Granted: going until the receiver reports everything, unless it stopped.
    assert_eq!(link_state("granted", None, false), S::Transferring);
    assert_eq!(link_state("granted", Some(("accepted", false)), false), S::Transferring);
    assert_eq!(link_state("granted", Some(("offered", false)), false), S::Transferring);
    assert_eq!(link_state("granted", Some(("completed", false)), false), S::Done);
    assert_eq!(link_state("granted", Some(("accepted", true)), false), S::Interrupted);
    assert_eq!(link_state("granted", Some(("declined", false)), false), S::Interrupted);
    assert_eq!(link_state("granted", Some(("canceled", false)), false), S::Interrupted);
    // A send that stopped before any transfer existed, after the grant was spent.
    assert_eq!(link_state("granted", None, true), S::Interrupted);
    // Before the grant the link can still carry a send, so it stays redeemed.
    assert_eq!(link_state("redeemed", None, true), S::Redeemed);
}

#[test]
fn a_send_failure_is_typed_only_when_a_front_end_can_tell_it_apart() {
    use super::{SendFailure, SendLinkCallError, SendLinkCallKind};
    use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode as Code;
    use yadorilink_send::{DialReason, SendError};
    let io_full = || std::io::Error::from(std::io::ErrorKind::StorageFull);
    let cases: Vec<(SendFailure, Option<Code>)> = vec![
        (SendError::Io(io_full()).into(), Some(Code::SendNoSpace)),
        (
            SendError::DialFailed {
                device_id: "d".into(),
                reason: DialReason::NoResponse,
                detail: "x".into(),
            }
            .into(),
            Some(Code::SendPeerUnreachable),
        ),
        (
            SendError::DialFailed {
                device_id: "d".into(),
                reason: DialReason::LocalNetworkBlocked,
                detail: "x".into(),
            }
            .into(),
            Some(Code::SendLocalNetworkBlocked),
        ),
        (SendError::SenderGone("d".into()).into(), Some(Code::SendPeerUnreachable)),
        (SendError::NoKnownAddress("d".into()).into(), Some(Code::SendPeerUnreachable)),
        (SendError::ReceiverStalled.into(), Some(Code::SendInterrupted)),
        (SendError::TransferCanceled("t".into()).into(), Some(Code::SendInterrupted)),
        (SendError::UnknownTransfer("t".into()).into(), None),
        ("plain".to_string().into(), None),
        (
            SendLinkCallError { kind: SendLinkCallKind::NotFound, message: "m".into() }.into(),
            Some(Code::SendLinkInvalid),
        ),
        (
            SendLinkCallError { kind: SendLinkCallKind::SignInRequired, message: "m".into() }
                .into(),
            Some(Code::LocalIdentityUnavailable),
        ),
        (
            SendLinkCallError { kind: SendLinkCallKind::Unreachable, message: "m".into() }.into(),
            Some(Code::CoordinationTransport),
        ),
        (SendLinkCallError { kind: SendLinkCallKind::Other, message: "m".into() }.into(), None),
    ];
    for (failure, code) in cases {
        assert_eq!(failure.code, code, "{}", failure.message);
    }
}

#[tokio::test]
async fn link_send_waits_for_service_then_reports_retryable_not_ready() {
    let (state, _dir) = device("device-early", 9);
    let svc = super::SendTransferService::new(state.clone());
    // Never up within the window: typed retryable refusal, nothing recorded on any link.
    let Err(err) = svc.wait_for_service(Duration::from_millis(50)).await else {
        panic!("no service was published");
    };
    assert_eq!(
        err.code,
        Some(yadorilink_ipc_proto::daemonctl::ApplicationErrorCode::CoordinationTransport)
    );
    assert!(err.message.contains("try again"), "{}", err.message);

    // Published while the caller is waiting: the wait returns it.
    let stack = Arc::new(
        SyncStack::spawn(state.clone(), yadorilink_sync_substrate::NetworkConfig::direct_only())
            .await
            .expect("stack starts"),
    );
    let send_dir = tempfile::tempdir().unwrap();
    {
        let state = state.clone();
        let dir = send_dir.path().to_path_buf();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(700)).await;
            state.install_peer_session_driver(PeerSessionDriver::start(state.clone(), stack));
            let _ = super::run(state, dir).await;
        });
    }
    assert!(svc.wait_for_service(STEP).await.is_ok());
}

/// Records on `local`'s Track Send store an accepted offer to `peer` made under the Send link
/// `link_id`.
fn accepted_link_offer(local: &Device, peer: &Device, link_id: &str) {
    let store = yadorilink_send::store::SendStore::open(
        local._dirs.1.path().join("send").join("store.sqlite3"),
    )
    .expect("the Track Send store opens");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        as i64;
    store
        .insert_outbound_offered(
            "link-offer",
            "recipient",
            &peer.key(),
            "/nowhere",
            &SendManifest { link_id: link_id.to_string(), ..Default::default() },
            now,
        )
        .expect("offer recorded");
    store.mark_outbound_acked("link-offer", now).expect("offer accepted");
}

/// The recipient of a Send link is on another account, so the sender's netmap never lists it, and
/// the grant it came in with is gone minutes after the offer. The link's own offer keeps
/// admitting it, and only it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_links_recipient_off_the_netmap_is_admitted_by_its_offer_after_the_grant_is_gone() {
    let alice = start(ALICE, 71).await;
    let carol = start(CAROL, 72).await;
    let dave = start("dave", 73).await;
    // Alice's netmap lists neither: no grant is on record either.
    accepted_link_offer(&alice, &carol, "link-1");

    assert!(
        ungranted_offer(&carol, &alice).await.is_some(),
        "the recipient of a link's offer is admitted without a grant or a netmap entry"
    );
    assert!(
        ungranted_offer(&dave, &alice).await.is_none(),
        "a device the link was not offered to is not"
    );
}

/// Two Send links from one sender to one receiving device are two live grants for one key at the
/// same time; each offer is checked against its own, and neither displaces the other.
#[tokio::test]
async fn two_grants_for_one_sender_key_are_both_found_by_their_own_offer() {
    use super::DaemonDeviceDirectory;
    use yadorilink_send::DeviceDirectory;
    let (state, _dir) = device(ALICE, 74);
    let key = [7u8; 32];
    let live = |grant_id: &str, nonce: &str| SendGrantPeer {
        device_id: "sender".to_string(),
        signing_key: key,
        reachability: Default::default(),
        grant_id: grant_id.to_string(),
        nonce: nonce.to_string(),
        expires_at_unix: i64::MAX,
    };
    state.record_send_grant_peer(live("grant-a", "nonce-a"));
    state.record_send_grant_peer(live("grant-b", "nonce-b"));
    assert!(state.send_grant_for(&key, "grant-a").is_some());
    assert!(
        state.send_grant_for(&key, "grant-b").is_some(),
        "the second did not replace the first"
    );
    assert!(state.send_grant_for(&[8u8; 32], "grant-a").is_none(), "grants are bound to the key");

    // Past the local checks the offer goes to the coordination service, which this state has no
    // address for: that is the answer for a grant on record with the right nonce.
    let directory = DaemonDeviceDirectory { state: Arc::downgrade(&state) };
    let verdict = |grant_id: &'static str, nonce: &'static str| {
        let directory = &directory;
        async move { directory.consume_grant(grant_id, nonce, &key).await.unwrap_err() }
    };
    assert!(verdict("grant-a", "nonce-a").await.contains("coordination plane"));
    assert!(verdict("grant-b", "nonce-b").await.contains("coordination plane"));
    assert!(verdict("grant-a", "nonce-b").await.contains("invalid"), "a nonce of another grant");
    assert!(verdict("grant-c", "nonce-a").await.contains("no pending"));
}

/// A Send link whose file list does not open is a typed refusal an app can tell from a generic
/// failure, not a plain message.
#[test]
fn an_unverifiable_preview_is_a_typed_refusal() {
    use crate::coordination_client::{SendLinkCallError, SendLinkCallKind};
    use crate::send_transfer::SendFailure;
    use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode;
    let failure = SendFailure::from(SendLinkCallError {
        kind: SendLinkCallKind::PreviewUnverified,
        message: "the list could not be verified".to_string(),
    });
    assert_eq!(failure.code, Some(ApplicationErrorCode::SendPreviewUnverified));
    assert_eq!(failure.message, "the list could not be verified");
    // A generic failure stays untyped.
    let other = SendFailure::from(SendLinkCallError {
        kind: SendLinkCallKind::Other,
        message: "odd".to_string(),
    });
    assert_eq!(other.code, None);
}
