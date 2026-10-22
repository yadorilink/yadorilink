#![cfg(test)]

use super::*;
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
use yadorilink_sync_substrate::{AdmitNone, AdmitWhen, NetworkConfig};

/// One device's iroh endpoint on loopback, answering Track Send's ALPN.
///
/// Who may open a Track Send connection to it is `admitted`, standing in
/// for the daemon's grant/accepted-offer admission; nobody may open a sync
/// connection. The grant gate this module tests is enforced at the
/// application layer (`handle_offer`) on top of that admission, so proving
/// it needs the same real handshake and ALPN routing production uses.
struct TestEndpoint {
    node: SubstrateNode,
    key: [u8; 32],
    admitted: Arc<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>>,
    inbound: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<TrackSendConnection>>>,
}

impl TestEndpoint {
    /// Let `key` open Track Send connections to this endpoint.
    fn admit(&self, key: [u8; 32]) {
        self.admitted.lock().unwrap().insert(key);
    }

    /// The inbound Track Send connections; one owner.
    fn take_inbound(&self) -> tokio::sync::mpsc::Receiver<TrackSendConnection> {
        self.inbound.lock().unwrap().take().expect("the inbound queue has exactly one owner")
    }

    /// How another device's directory would describe this one.
    fn resolved(&self, device_id: &str) -> ResolvedDevice {
        let address = self.node.local_address();
        ResolvedDevice {
            device_id: device_id.to_string(),
            signing_key: self.key,
            direct_addresses: address.direct_addrs().copied().collect(),
            relay_urls: Vec::new(),
        }
    }
}

async fn raw_endpoint() -> Arc<TestEndpoint> {
    let secret: [u8; 32] = rand_key();
    let admitted: Arc<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>> = Arc::default();
    let admission = {
        let admitted = admitted.clone();
        AdmitWhen::new(move |peer: &PeerId| admitted.lock().unwrap().contains(peer.as_bytes()))
    };
    let (inbound_tx, inbound) = tokio::sync::mpsc::channel(16);
    let (node, _sync_inbound) = SubstrateNode::spawn_as_device(
        secret,
        NetworkConfig::direct_only().with_track_send(admission, inbound_tx),
        Arc::new(AdmitNone),
    )
    .await
    .expect("bind endpoint");
    let key = *node.peer_id().as_bytes();
    Arc::new(TestEndpoint { node, key, admitted, inbound: std::sync::Mutex::new(Some(inbound)) })
}

/// A fresh random 32-byte secret, from the same source transfer ids use.
fn rand_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key
}

/// A fresh `SendService` over `endpoint`, backed by its own isolated
/// temp directory (kept alive by the returned guard). Never starts
/// `run_inbound_dispatcher` itself -- a caller that needs this service
/// to actually receive connections spawns that separately with the
/// endpoint's inbound queue, exactly like production (`send_transfer::run`)
/// does.
fn make_service(
    endpoint: &TestEndpoint,
    directory: Arc<dyn DeviceDirectory>,
) -> (Arc<SendService>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store_db_path = dir.path().join("store.sqlite3");
    let block_store_root = dir.path().join("blocks");
    let inbox_dir = dir.path().join("inbox");
    let service = SendService::new(
        endpoint.node.clone(),
        store_db_path,
        block_store_root,
        directory,
        inbox_dir,
    )
    .expect("SendService::new should succeed against a fresh temp directory");
    (Arc::new(service), dir)
}

/// `make_service`, with the service serving `endpoint`'s inbound Track
/// Send connections.
fn serving_service(
    endpoint: &TestEndpoint,
    directory: Arc<dyn DeviceDirectory>,
) -> (Arc<SendService>, tempfile::TempDir) {
    let (service, guard) = make_service(endpoint, directory);
    tokio::spawn(service.clone().run_inbound_dispatcher(endpoint.take_inbound()));
    (service, guard)
}

/// A single-use, in-memory stand-in for the coordination plane's
/// `send_authorizations` table -- atomic issue/consume, bound to the
/// presenting connection's authenticated key, matching
/// `DaemonDeviceDirectory::consume_grant`'s own doc comment for the
/// real primitive, without needing a real D1/coordination worker for
/// these tests.
#[derive(Default)]
struct FakeGrantStore {
    inner: std::sync::Mutex<FakeGrantStoreInner>,
}

#[derive(Default)]
struct FakeGrantStoreInner {
    grants: HashMap<String, FakeGrantRecord>,
    last_issued: Option<(String, String)>,
}

struct FakeGrantRecord {
    nonce: String,
    sender_key: [u8; 32],
    consumed: bool,
}

impl FakeGrantStore {
    fn issue(&self, grant_id: &str, nonce: &str, sender_key: [u8; 32]) {
        let mut inner = self.inner.lock().unwrap();
        inner.grants.insert(
            grant_id.to_string(),
            FakeGrantRecord { nonce: nonce.to_string(), sender_key, consumed: false },
        );
        inner.last_issued = Some((grant_id.to_string(), nonce.to_string()));
    }

    fn last_issued(&self) -> (String, String) {
        self.inner.lock().unwrap().last_issued.clone().expect("a grant must have been issued")
    }

    /// One lock guards the whole check-then-mark sequence, so two
    /// presentations of the same grant can never both observe it as
    /// unconsumed -- the same atomicity
    /// `DaemonDeviceDirectory::consume_grant`'s own doc comment
    /// describes for the real coordination-plane primitive.
    fn consume(
        &self,
        grant_id: &str,
        nonce: &str,
        peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        let Some(record) = inner.grants.get_mut(grant_id) else {
            return Err("send authorization is invalid, expired, or already used".to_string());
        };
        if record.consumed || record.nonce != nonce || &record.sender_key != peer_key {
            return Err("send authorization is invalid, expired, or already used".to_string());
        }
        record.consumed = true;
        Ok(())
    }
}

/// A `DeviceDirectory` for the RECEIVING side of these tests.
/// `consume_grant` either delegates to a real (fake) grant store, or --
/// when `grants` is `None` -- fails closed exactly like the trait's own
/// default, modeling a directory with ZERO grant capability at all (the
/// cross-account-shaped case: nothing this directory could ever have
/// granted). `resolve` always returns `None`: `handle_offer` never
/// calls it (only `offer_send` used to, before this fix), so these
/// tests keep it inert on purpose rather than implying it takes part in
/// the check being tested. `request_grant` is never overridden: none of
/// these tests drive `offer_send` from the receiving side.
struct TestDirectory {
    grants: Option<Arc<FakeGrantStore>>,
    device_labels: HashMap<[u8; 32], String>,
}

#[async_trait::async_trait]
impl DeviceDirectory for TestDirectory {
    fn resolve(&self, _device_query: &str) -> Option<ResolvedDevice> {
        None
    }

    fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String> {
        self.device_labels.get(signing_key).cloned()
    }

    async fn consume_grant(
        &self,
        grant_id: &str,
        grant_nonce: &str,
        peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        match &self.grants {
            Some(store) => store.consume(grant_id, grant_nonce, peer_key),
            None => Err("this directory does not support Track Send grants".to_string()),
        }
    }
}

/// A `DeviceDirectory` for the SENDING side of the positive-control
/// test at the bottom of this module: `request_grant` mints a real,
/// single-use grant against a shared `FakeGrantStore`, bound to
/// `sender_key` -- the same shape `DaemonDeviceDirectory::request_grant`
/// produces against the real coordination plane. `resolve` is always
/// `None`: the point of that test is that `offer_send` completes with
/// NO ordinary netmap relationship at all.
struct GrantingDirectory {
    sender_key: [u8; 32],
    grants: Arc<FakeGrantStore>,
    target: ResolvedDevice,
}

#[async_trait::async_trait]
impl DeviceDirectory for GrantingDirectory {
    fn resolve(&self, _device_query: &str) -> Option<ResolvedDevice> {
        None
    }

    fn device_id_for_key(&self, _signing_key: &[u8; 32]) -> Option<String> {
        None
    }

    async fn request_grant(&self, receiver_device_query: &str) -> Option<GrantedDevice> {
        if receiver_device_query != self.target.device_id {
            return None;
        }
        let grant_id = format!("grant-{}", uuid::Uuid::new_v4());
        let grant_nonce = format!("nonce-{}", uuid::Uuid::new_v4());
        self.grants.issue(&grant_id, &grant_nonce, self.sender_key);
        Some(GrantedDevice {
            device: self.target.clone(),
            grant_id,
            grant_nonce,
            // Effectively never expires within a test's lifetime.
            expires_at_unix: i64::MAX,
        })
    }
}

/// Dials `addr` over send-ALPN and presents a bare-bones manifest offer
/// carrying exactly the `grant_id`/`grant_nonce` given -- the raw
/// wire-level primitive every test below drives directly, bypassing
/// `offer_send` entirely, so each test controls precisely what an
/// adversarial or merely non-compliant sender presents (including
/// presenting nothing at all).
async fn raw_offer(
    dialer: &TestEndpoint,
    target: &TestEndpoint,
    transfer_id: &str,
    grant_id: &str,
    grant_nonce: &str,
) -> SendManifestAck {
    raw_offer_manifest(
        dialer,
        target,
        SendManifest {
            transfer_id: transfer_id.to_string(),
            files: vec![],
            total_size: 0,
            offered_at_unix_nanos: 0,
        },
        grant_id,
        grant_nonce,
    )
    .await
}

/// [`raw_offer`] presenting the given manifest as it stands.
async fn raw_offer_manifest(
    dialer: &TestEndpoint,
    target: &TestEndpoint,
    manifest: SendManifest,
    grant_id: &str,
    grant_nonce: &str,
) -> SendManifestAck {
    let connection =
        dialer.node.connect_track_send(&target.resolved("target").address()).await.expect(
            "a Track Send dial completes -- transport-layer admission is not this test's \
         concern, only the application-layer grant check is",
        );
    let (mut send, mut recv) = connection.open_stream().await.expect("open a stream");
    write_message(
        &mut send,
        &SendEnvelope {
            payload: Some(send_envelope::Payload::Manifest(manifest)),
            grant_id: grant_id.to_string(),
            grant_nonce: grant_nonce.to_string(),
        },
    )
    .await
    .unwrap();
    send.finish().ok();
    let ack: SendManifestAck = read_message(&mut recv).await.unwrap();
    connection.close(close_code::DONE, b"test offer");
    ack
}

/// A peer the Track Send ALPN admits (because this device expects it for
/// some other reason -- an earlier grant, an accepted offer) and a
/// receiving directory that DOES have real grant capability, so a compliant
/// sender genuinely could have obtained and presented one. An offer that
/// presents no grant at all must still be rejected: being admitted on the
/// ALPN is never, by itself, sufficient to deliver a Send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ungranted_offer_from_an_admitted_peer_is_rejected() {
    let dialer = raw_endpoint().await;
    let acceptor = raw_endpoint().await;
    acceptor.admit(dialer.key);

    let grants = Arc::new(FakeGrantStore::default());
    let directory: Arc<dyn DeviceDirectory> = Arc::new(TestDirectory {
        grants: Some(grants),
        device_labels: HashMap::from([(dialer.key, "dialer-device".to_string())]),
    });
    let (service, _dir_guard) = serving_service(&acceptor, directory);

    let ack = raw_offer(&dialer, &acceptor, "ungranted-admitted", "", "").await;

    assert!(
        !ack.accepted,
        "an admitted peer must not be able to complete a Send offer without presenting a grant"
    );
    assert!(!ack.reason.is_empty(), "a rejection must carry a reason");
    assert!(
        service.list_inbox().unwrap().is_empty(),
        "a rejected offer must leave no trace, not even a rejected-but-stored inbox entry"
    );
}

/// The cross-account-shaped variant: an admitted peer whose receiving
/// directory has ZERO grant capability whatsoever -- not merely "this
/// sender didn't present one", but "nothing here could ever have granted
/// it" (the trait's own default `consume_grant`). Must still be rejected
/// outright.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ungranted_offer_from_an_admitted_peer_with_zero_grant_capability_is_rejected() {
    let dialer = raw_endpoint().await;
    let acceptor = raw_endpoint().await;
    acceptor.admit(dialer.key);

    let directory: Arc<dyn DeviceDirectory> =
        Arc::new(TestDirectory { grants: None, device_labels: HashMap::new() });
    let (service, _dir_guard) = serving_service(&acceptor, directory);

    let ack = raw_offer(&dialer, &acceptor, "ungranted-cross-account-shaped", "", "").await;

    assert!(!ack.accepted, "a directory with zero grant capability must still reject cleanly");
    assert!(service.list_inbox().unwrap().is_empty());
}

/// A genuinely valid grant authorizes exactly ONE offer, not unlimited
/// offers from an already-admitted sender -- a second presentation of the
/// SAME grant, and a third offer that omits `grant_id` entirely while
/// still admitted from the first grant, must both be rejected. Otherwise a
/// sender could omit `grant_id` on every offer after its first and ride
/// that one grant admission indefinitely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_consumed_grant_cannot_authorize_a_second_or_third_offer() {
    let dialer = raw_endpoint().await;
    let acceptor = raw_endpoint().await;
    // Admitted because of the grant below -- the groupless-sender shape.
    acceptor.admit(dialer.key);

    let grants = Arc::new(FakeGrantStore::default());
    grants.issue("grant-1", "nonce-1", dialer.key);
    let directory: Arc<dyn DeviceDirectory> = Arc::new(TestDirectory {
        grants: Some(grants),
        device_labels: HashMap::from([(dialer.key, "sender-device".to_string())]),
    });
    let (service, _dir_guard) = serving_service(&acceptor, directory);

    let first = raw_offer(&dialer, &acceptor, "transfer-3a", "grant-1", "nonce-1").await;
    assert!(
        first.accepted,
        "a genuinely valid, unconsumed grant must authorize its offer: {}",
        first.reason
    );

    let second = raw_offer(&dialer, &acceptor, "transfer-3b", "grant-1", "nonce-1").await;
    assert!(
        !second.accepted,
        "a second presentation of an already-consumed grant must be rejected"
    );

    let third = raw_offer(&dialer, &acceptor, "transfer-3c", "", "").await;
    assert!(
        !third.accepted,
        "omitting grant_id must not let an already-admitted sender make unlimited offers off \
         one grant admission"
    );

    let inbox = service.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1, "only the single genuinely-granted offer should be recorded");
    assert_eq!(inbox[0].transfer_id, "transfer-3a");
}

/// The positive control: `offer_send` itself, driven end to end with NO
/// ordinary netmap relationship on either side at all, still completes
/// -- because it always obtains a real grant via `request_grant` rather
/// than needing `resolve` to succeed first. Proves the gate does not
/// merely reject everything: a compliant sender presenting a real,
/// freshly-obtained grant is still accepted, and that same grant cannot
/// then be replayed over the raw wire path either. Also pins the sender's
/// half of pull admission: once the offer is accepted, the sender expects
/// the receiver back (`expects_pull_from`), and not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_send_obtains_and_attaches_a_real_grant_with_no_netmap_relationship_at_all() {
    let sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;

    let grants = Arc::new(FakeGrantStore::default());
    let receiver_directory: Arc<dyn DeviceDirectory> = Arc::new(TestDirectory {
        grants: Some(grants.clone()),
        device_labels: HashMap::from([(sender_endpoint.key, "sender-device".to_string())]),
    });
    let (receiver_service, _receiver_dir_guard) =
        serving_service(&receiver_endpoint, receiver_directory);
    // Outside this crate's own scope in production: the coordination
    // plane pushes the grant to the RECEIVER over its netmap
    // subscription, and the daemon's Track Send admission then lets the
    // sender's key in for the grant's lifetime. This crate has no idea a
    // coordination plane exists, so this test stands in for that push
    // having already landed before the sender's offer connection arrives.
    receiver_endpoint.admit(sender_endpoint.key);

    let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(GrantingDirectory {
        sender_key: sender_endpoint.key,
        grants: grants.clone(),
        target: receiver_endpoint.resolved("receiver-device"),
    });
    let (sender_service, _sender_dir_guard) = make_service(&sender_endpoint, sender_directory);
    assert!(
        !sender_service.expects_pull_from(&receiver_endpoint.key),
        "nothing has been offered yet"
    );

    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("hello.txt");
    std::fs::write(&source_path, b"hello via a fresh grant, no netmap relationship at all")
        .unwrap();

    let outcome = sender_service
        .offer_send(&source_path, "receiver-device")
        .await
        .expect("offer_send should succeed once a real grant is obtained");
    assert_eq!(outcome.files_offered, vec!["hello.txt".to_string()]);
    assert!(
        sender_service.expects_pull_from(&receiver_endpoint.key),
        "an accepted offer's receiver may come back to pull"
    );
    assert!(
        !sender_service.expects_pull_from(&sender_endpoint.key),
        "only the device the offer was accepted by"
    );

    let inbox = receiver_service.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].transfer_id, outcome.transfer_id);

    // The exact grant `offer_send` minted and consumed above must not
    // be replayable over the raw wire path either.
    let (used_grant_id, used_grant_nonce) = grants.last_issued();
    let replay = raw_offer(
        &sender_endpoint,
        &receiver_endpoint,
        "replay-attempt",
        &used_grant_id,
        &used_grant_nonce,
    )
    .await;
    assert!(!replay.accepted, "the grant offer_send already consumed must not be replayable");
}

/// A receiver that answers `SendManifestAck{accepted:false}` must not
/// be able to dial the sender back afterward and pull the file content
/// anyway. `offer_send` moves the outbound row to
/// `OutboundStatus::Rejected` once it observes the rejection, and
/// `handle_pull` requires `OutboundStatus::Acked` before serving any
/// chunk -- this drives both halves together over real connections, in
/// the exact two-connection shape (one for the offer, a wholly separate
/// one for the pull) a real receiver uses. The sender also stops
/// expecting that receiver (`expects_pull_from`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_that_rejects_the_offer_cannot_later_pull_the_content() {
    let sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;
    // Stands in for the coordination plane's own push of the grant to
    // the receiver, exactly as the positive-control test does.
    receiver_endpoint.admit(sender_endpoint.key);
    // The sender still admits the receiver's key while the grant it
    // requested is live, so a pull attempt reaches `handle_pull` and must
    // be refused there.
    sender_endpoint.admit(receiver_endpoint.key);

    let grants = Arc::new(FakeGrantStore::default());
    let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(GrantingDirectory {
        sender_key: sender_endpoint.key,
        grants: grants.clone(),
        target: receiver_endpoint.resolved("receiver-device"),
    });
    // Production parity: `send_transfer::run` always runs the dispatcher,
    // so the sender really does serve inbound pulls.
    let (sender_service, _sender_guard) = serving_service(&sender_endpoint, sender_directory);

    let secret = b"content a rejecting receiver must never get".to_vec();
    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("secret.txt");
    std::fs::write(&source_path, &secret).unwrap();

    // A hand-rolled receiver that rejects every offer but remembers the
    // transfer id it saw in the manifest, so it can try pulling by id
    // afterward exactly like a real (malicious or merely buggy) client
    // could.
    let mut inbox = receiver_endpoint.take_inbound();
    let (id_tx, id_rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let connection = inbox.recv().await.expect("an inbound offer");
        let (mut send, mut recv) = connection.accept_stream().await.expect("offer stream");
        let envelope: SendEnvelope = read_message(&mut recv).await.unwrap();
        let Some(send_envelope::Payload::Manifest(manifest)) = envelope.payload else {
            panic!("expected a manifest offer");
        };
        write_message(
            &mut send,
            &SendManifestAck { accepted: false, reason: "receiver rejects this offer".to_string() },
        )
        .await
        .unwrap();
        send.finish().ok();
        send.flushed(Duration::from_secs(5)).await;
        let _ = id_tx.send(manifest.transfer_id);
    });

    let err = sender_service
        .offer_send(&source_path, "receiver-device")
        .await
        .expect_err("the receiver rejected, so offer_send must fail");
    assert!(matches!(err, SendError::OfferRejected(_)), "got {err:?}");
    let transfer_id = id_rx.await.expect("the receiver saw a transfer id");
    assert!(
        !sender_service.expects_pull_from(&receiver_endpoint.key),
        "a rejected offer gives the receiver no reason to be let back in"
    );

    // Now the rejecting receiver dials the sender BACK, on a fresh
    // connection, and pulls -- this must be refused at the application
    // layer, in `handle_pull` itself.
    let connection = receiver_endpoint
        .node
        .connect_track_send(&sender_endpoint.resolved("sender").address())
        .await
        .expect("the sender still admits this key on the Track Send ALPN");
    let (mut send, mut recv) = connection.open_stream().await.unwrap();
    write_message(
        &mut send,
        &SendEnvelope {
            payload: Some(send_envelope::Payload::Pull(ChunkPullRequest {
                transfer_id,
                file_index: 0,
                start_chunk_index: 0,
            })),
            grant_id: String::new(),
            grant_nonce: String::new(),
        },
    )
    .await
    .unwrap();
    send.finish().ok();

    let message: ChunkStreamMessage =
        tokio::time::timeout(Duration::from_secs(15), read_message(&mut recv))
            .await
            .expect("the sender answered the pull within 15s")
            .unwrap();
    match message.payload {
        Some(chunk_stream_message::Payload::Rejected(r)) => {
            assert!(!r.reason.is_empty(), "a rejection must carry a reason");
        }
        Some(chunk_stream_message::Payload::Header(h)) => {
            let body = read_body(&mut recv, h.size as usize).await.unwrap();
            panic!(
                "a receiver that rejected the offer must not be able to pull the content, \
                 but the pull was served: {} bytes, matches source: {}",
                body.len(),
                body == secret
            );
        }
        None => panic!("empty message"),
    }
}

/// A `DeviceDirectory` that can resolve a target through ordinary
/// netmap connectivity (`resolve` -> `Some`, a real reachable address)
/// but has ZERO grant capability (`request_grant` falls through to the
/// trait's own `None` default) -- the shape a same-account device this
/// daemon can already reach over sync, but for which the coordination
/// plane will not currently mint a Send grant, would present.
struct NetmapOnlyDirectory {
    target: ResolvedDevice,
}

#[async_trait::async_trait]
impl DeviceDirectory for NetmapOnlyDirectory {
    fn resolve(&self, device_query: &str) -> Option<ResolvedDevice> {
        (device_query == self.target.device_id).then(|| self.target.clone())
    }
    fn device_id_for_key(&self, _signing_key: &[u8; 32]) -> Option<String> {
        None
    }
}

/// The negative control for `offer_send`'s own half of the grant
/// requirement: a target `resolve` can reach through ordinary netmap
/// connectivity, but for which no grant is obtainable, must make
/// `offer_send` fail with `NoKnownDeviceKey` BEFORE it ever dials --
/// not fall back to sending an ungranted offer the receiver then has to
/// reject on its own. The positive-control test above cannot exercise
/// this guard by itself, because its own `resolve` always returns
/// `None`; this test is the one that actually proves `offer_send` never
/// treats netmap-resolvability as a substitute for a grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_send_refuses_a_netmap_resolvable_target_when_no_grant_can_be_obtained() {
    let sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;
    // Even admitted on the receiver's side, nothing may be sent ungranted.
    receiver_endpoint.admit(sender_endpoint.key);

    let receiver_directory: Arc<dyn DeviceDirectory> =
        Arc::new(TestDirectory { grants: None, device_labels: HashMap::new() });
    let (receiver_service, _receiver_guard) =
        serving_service(&receiver_endpoint, receiver_directory);

    let sender_directory: Arc<dyn DeviceDirectory> =
        Arc::new(NetmapOnlyDirectory { target: receiver_endpoint.resolved("receiver-device") });
    let (sender_service, _sender_guard) = make_service(&sender_endpoint, sender_directory);

    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("hello.txt");
    std::fs::write(&source_path, b"ordinary netmap peer, no grant available").unwrap();

    let error = sender_service
        .offer_send(&source_path, "receiver-device")
        .await
        .expect_err("a target with no obtainable grant must not be sendable to");
    assert!(
        matches!(error, SendError::NoKnownDeviceKey(_)),
        "offer_send must fail on the missing grant BEFORE dialing, not fall back to an \
         ungranted offer the receiver then rejects; got: {error:?}"
    );
    assert!(
        receiver_service.list_inbox().unwrap().is_empty(),
        "no offer should have reached the receiver at all"
    );
}

// ---- pull-loop validation against the receiver's own manifest -------
//
// `pull_file` is exercised directly (bypassing `receive_transfer`'s own
// store/destination-directory bookkeeping, which is orthogonal to what
// is being proven here) against a hand-rolled "sender" that answers a
// pull with whatever a real, already-accepted `SendService` never
// would -- a wrong chunk index, a chunk declared a different size than
// the manifest says, a chunk whose body does not hash to what the
// manifest recorded, or more chunks than the manifest has entries for.
// The point in every case is the same: an accepted sender is trusted
// for network reachability, never for chunk content, size, order, or
// count -- this device's own manifest, already durably on disk before
// any of these pulls dial out, is what every received chunk is
// checked against.

/// A `SendFileEntry` whose `chunk_hashes`/`chunk_size`/`size` are
/// derived directly from `chunk_bodies`, exactly the way
/// `build_outbound_manifest` would have produced them for a real file
/// split into these exact chunks -- so `pull_file`'s validation against
/// this entry is checked against the same shape of manifest a real
/// offer would carry, not a hand-waved stand-in.
fn pull_test_entry(chunk_size: u32, chunk_bodies: &[&[u8]]) -> SendFileEntry {
    let chunk_hashes = chunk_bodies
        .iter()
        .map(|body| hex::decode(hash_block_bytes(body)).expect("hex-decodes"))
        .collect();
    let size: u64 = chunk_bodies.iter().map(|body| body.len() as u64).sum();
    SendFileEntry { relative_path: "pulled.bin".to_string(), size, chunk_size, chunk_hashes }
}

/// Accepts exactly one inbound Track Send connection on `endpoint`,
/// confirms it carries a `ChunkPullRequest` (not a manifest offer), and
/// then writes exactly the `(header, body)` pairs given, in order,
/// before finishing the stream -- a hand-rolled "sender" answering a
/// pull with whatever a test wants to present, without a second real
/// `SendService` involved at all.
async fn fake_pull_responder(endpoint: Arc<TestEndpoint>, responses: Vec<(ChunkHeader, Vec<u8>)>) {
    let mut inbox = endpoint.take_inbound();
    let connection = inbox.recv().await.expect("an inbound pull connection");
    let (mut send, mut recv) = connection.accept_stream().await.expect("pull stream");
    let envelope: SendEnvelope = read_message(&mut recv).await.unwrap();
    assert!(
        matches!(envelope.payload, Some(send_envelope::Payload::Pull(_))),
        "expected a chunk pull request, got {envelope:?}"
    );
    for (header, body) in responses {
        write_message(
            &mut send,
            &ChunkStreamMessage { payload: Some(chunk_stream_message::Payload::Header(header)) },
        )
        .await
        .unwrap();
        send.write_all(&body).await.unwrap();
    }
    send.finish().ok();
    send.flushed(Duration::from_secs(5)).await;
}

/// A real receiver `SendService`, plus a fake sender's raw endpoint
/// (already admitting the receiver's key on the Track Send ALPN, exactly
/// as a real sender's admission does for an accepted offer) and the
/// `ResolvedDevice` `pull_file` needs to dial it -- the shared setup
/// every test in this group starts from.
async fn receiver_and_fake_sender(
) -> (Arc<SendService>, tempfile::TempDir, Arc<TestEndpoint>, ResolvedDevice) {
    let fake_sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;
    fake_sender_endpoint.admit(receiver_endpoint.key);

    let receiver_directory: Arc<dyn DeviceDirectory> =
        Arc::new(TestDirectory { grants: None, device_labels: HashMap::new() });
    let (receiver_service, receiver_guard) = make_service(&receiver_endpoint, receiver_directory);
    let sender = fake_sender_endpoint.resolved("fake-sender");
    (receiver_service, receiver_guard, fake_sender_endpoint, sender)
}

/// A chunk header whose declared `size` disagrees with what this
/// device's own manifest says chunk 0 of a single-chunk file must be
/// must be rejected -- and rejected BEFORE the body is read, since an
/// unchecked peer-supplied `size` is exactly what would otherwise size
/// an unbounded allocation in `read_body`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_file_rejects_a_chunk_whose_declared_size_disagrees_with_the_manifest() {
    let (receiver_service, _receiver_guard, fake_sender_endpoint, sender) =
        receiver_and_fake_sender().await;
    let entry = pull_test_entry(5, &[b"hello"]);

    tokio::spawn(fake_pull_responder(
        fake_sender_endpoint,
        vec![(ChunkHeader { chunk_index: 0, size: 999, last_chunk: true }, b"hello".to_vec())],
    ));

    let error = tokio::time::timeout(
        Duration::from_secs(15),
        receiver_service.pull_file(&sender, "t1", 0, &entry, 0),
    )
    .await
    .expect("pull_file must not hang on an oversized declared chunk size")
    .expect_err("a chunk whose declared size disagrees with the manifest must be rejected");
    assert!(matches!(error, SendError::Protocol(_)), "got {error:?}");
}

/// A chunk whose body does not hash to what this device's own manifest
/// recorded for that chunk index must be rejected -- and rejected
/// before `block_store.put` ever durably commits it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_file_rejects_a_chunk_that_fails_hash_verification() {
    let (receiver_service, _receiver_guard, fake_sender_endpoint, sender) =
        receiver_and_fake_sender().await;
    let entry = pull_test_entry(5, &[b"hello"]);

    tokio::spawn(fake_pull_responder(
        fake_sender_endpoint,
        vec![(ChunkHeader { chunk_index: 0, size: 5, last_chunk: true }, b"WRONG".to_vec())],
    ));

    let error = tokio::time::timeout(
        Duration::from_secs(15),
        receiver_service.pull_file(&sender, "t1", 0, &entry, 0),
    )
    .await
    .expect("pull_file must not hang on a hash-mismatched chunk")
    .expect_err("a chunk that does not hash to the manifest's entry must be rejected");
    assert!(
        matches!(error, SendError::ChunkHashMismatch { file_index: 0, chunk_index: 0 }),
        "got {error:?}"
    );

    // The mismatched body must never have reached the block store --
    // the receiver's own manifest hash is checked before `put`, not
    // after.
    let expected_hex = hex::encode(&entry.chunk_hashes[0]);
    let present =
        receiver_service.block_store.present_blocks(std::slice::from_ref(&expected_hex)).unwrap();
    assert_eq!(present, vec![false], "the expected chunk hash must not be present");
}

/// A connection that ends while a chunk body is arriving is a broken connection, not a fault of
/// this device's disk: it is reported as the other device being unreachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_that_ends_inside_a_chunk_is_reported_as_unreachable() {
    let (receiver_service, _receiver_guard, fake_sender_endpoint, sender) =
        receiver_and_fake_sender().await;
    let entry = pull_test_entry(5, &[b"hello"]);

    tokio::spawn(fake_pull_responder(
        fake_sender_endpoint,
        vec![(ChunkHeader { chunk_index: 0, size: 5, last_chunk: true }, b"hel".to_vec())],
    ));

    let error = tokio::time::timeout(
        Duration::from_secs(15),
        receiver_service.pull_file(&sender, "t1", 0, &entry, 0),
    )
    .await
    .expect("pull_file must not hang on a body cut short")
    .expect_err("a body cut short is an error");
    assert_eq!(error.failure_code(), crate::error::failure::UNREACHABLE, "got {error:?}");
}

/// However many extra chunks a peer keeps sending, and whatever it sets
/// `last_chunk` to, `pull_file` must stop reading once it has received
/// as many chunks as this device's own manifest says the file has --
/// never fewer (an early, dishonest `last_chunk: true` is a separate,
/// pre-existing concern this test does not touch), and never more.
/// Proven by a fake sender that never sets `last_chunk: true` at all,
/// and would fail a THIRD chunk's own size validation if `pull_file`
/// ever asked for it (`chunk_byte_size` has no chunk index 2 in a
/// 2-chunk manifest) -- so the pull only succeeds if the loop stopped
/// itself, by count, without ever issuing that third read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_file_stops_at_the_manifests_chunk_count_regardless_of_last_chunk() {
    let (receiver_service, _receiver_guard, fake_sender_endpoint, sender) =
        receiver_and_fake_sender().await;
    let entry = pull_test_entry(5, &[b"AAAAA", b"BB"]);

    tokio::spawn(fake_pull_responder(
        fake_sender_endpoint,
        vec![
            // Neither chunk claims to be the last one -- a buggy or
            // malicious sender that never sends a true `last_chunk`.
            (ChunkHeader { chunk_index: 0, size: 5, last_chunk: false }, b"AAAAA".to_vec()),
            (ChunkHeader { chunk_index: 1, size: 2, last_chunk: false }, b"BB".to_vec()),
            // Would blow up `chunk_byte_size` (out of range for a
            // 2-chunk manifest) if `pull_file` ever read this far.
            (
                ChunkHeader { chunk_index: 2, size: 999, last_chunk: true },
                b"should never be read".to_vec(),
            ),
        ],
    ));

    tokio::time::timeout(
        Duration::from_secs(15),
        receiver_service.pull_file(&sender, "t1", 0, &entry, 0),
    )
    .await
    .expect("pull_file must not hang")
    .expect(
        "pull_file must stop cleanly at the manifest's own chunk count, \
         never reading the peer's extra, out-of-range third chunk",
    );

    // Both genuine chunks were still durably received.
    let hashes: Vec<String> = entry.chunk_hashes.iter().map(hex::encode).collect();
    let present = receiver_service.block_store.present_blocks(&hashes).unwrap();
    assert_eq!(present, vec![true, true], "both real chunks must have been stored");
}

// ---- ack-then-immediate-pull ordering --------------------------------

/// A `DeviceDirectory` for the RECEIVING side of the test below only:
/// unlike `TestDirectory` (used everywhere else in this module, which
/// never resolves anything -- see its own doc comment), this one CAN
/// resolve the sender back to a dialable address, because
/// `receive_transfer`'s pull-phase dial-back needs exactly that. Also
/// consumes grants against a real (fake) shared `FakeGrantStore`, like
/// `TestDirectory` does, since the offer this test drives needs one to
/// be accepted at all.
struct ReceiverWithResolvableSender {
    sender: ResolvedDevice,
    grants: Arc<FakeGrantStore>,
}

#[async_trait::async_trait]
impl DeviceDirectory for ReceiverWithResolvableSender {
    fn resolve(&self, device_query: &str) -> Option<ResolvedDevice> {
        (device_query == self.sender.device_id).then(|| self.sender.clone())
    }
    fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String> {
        (signing_key == &self.sender.signing_key).then(|| self.sender.device_id.clone())
    }
    async fn consume_grant(
        &self,
        grant_id: &str,
        grant_nonce: &str,
        peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        self.grants.consume(grant_id, grant_nonce, peer_key)
    }
}

/// Regression for the ack/pull reordering in `offer_send`:
/// `mark_outbound_acked` now runs BEFORE `connection.close()` (see that
/// call site's own comment) instead of after, so this device's own
/// record of an acceptance lands as early as it possibly can, narrowing
/// -- not eliminating -- the window in which a receiver that already
/// answered `accepted: true` and immediately dials back can hit
/// `handle_pull`'s `Acked` check first.
///
/// Races a real accept against a real, immediate pull attempt with no
/// artificial delay on either side -- the racing task starts polling
/// before `offer_send` has even been called, which is earlier than any
/// real client could react. A transient rejection here is therefore
/// still an expected, self-healing outcome (see `offer_send`'s own
/// comment: this is a narrowed race, not a closed one), so a bounded
/// number of quick retries is allowed -- but the pull must succeed,
/// and quickly, not require the kind of retry-with-backoff a real
/// networked race might.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receiver_can_pull_immediately_after_accepting_the_offer() {
    let sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;
    receiver_endpoint.admit(sender_endpoint.key);
    sender_endpoint.admit(receiver_endpoint.key);

    let grants = Arc::new(FakeGrantStore::default());
    let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(GrantingDirectory {
        sender_key: sender_endpoint.key,
        grants: grants.clone(),
        target: receiver_endpoint.resolved("receiver-device"),
    });
    let (sender_service, _sender_guard) = serving_service(&sender_endpoint, sender_directory);

    let receiver_directory: Arc<dyn DeviceDirectory> = Arc::new(ReceiverWithResolvableSender {
        sender: sender_endpoint.resolved("sender-device"),
        grants,
    });
    let (receiver_service, _receiver_guard) =
        serving_service(&receiver_endpoint, receiver_directory);

    let content = b"pulled right after acceptance, no meaningful delay".to_vec();
    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("race.txt");
    std::fs::write(&source_path, &content).unwrap();

    let receiver_for_race = receiver_service.clone();
    let racer = tokio::spawn(async move {
        // Polls the receiver's own inbox rather than sleeping -- picks
        // up the offer (and attempts the pull) as early as physically
        // possible on this task, which can be before the sender has
        // even read this receiver's own ack.
        let transfer_id = loop {
            if let Some(entry) = receiver_for_race.list_inbox().unwrap().into_iter().next() {
                break entry.transfer_id;
            }
            tokio::task::yield_now().await;
        };
        for attempt in 0..50 {
            match receiver_for_race.receive_transfer(&transfer_id, None).await {
                Ok(outcome) => return outcome,
                Err(_) if attempt < 49 => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => {
                    panic!("the pull never succeeded after 50 quick retries: {error}")
                }
            }
        }
        unreachable!("loop above always returns or panics")
    });

    sender_service
        .offer_send(&source_path, "receiver-device")
        .await
        .expect("a granted, accepted offer must succeed");

    let outcome = racer.await.expect("the racing pull task must not panic");
    assert_eq!(outcome.bytes_received, content.len() as u64);
    assert_eq!(outcome.files_received, vec!["race.txt".to_string()]);
}

/// A granted sender's manifest is still its own claim: one whose chunk size or
/// totals do not add up is rejected before it is recorded, so the pull never
/// sizes an allocation (a 4 GiB chunk) from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_granted_offer_with_an_inconsistent_manifest_is_rejected_and_not_recorded() {
    let dialer = raw_endpoint().await;
    let acceptor = raw_endpoint().await;
    acceptor.admit(dialer.key);

    let grants = Arc::new(FakeGrantStore::default());
    let directory: Arc<dyn DeviceDirectory> = Arc::new(TestDirectory {
        grants: Some(grants.clone()),
        device_labels: HashMap::from([(dialer.key, "sender-device".to_string())]),
    });
    let (service, _dir_guard) = serving_service(&acceptor, directory);

    let entry = |chunk_size: u32, size: u64, hashes: usize| SendFileEntry {
        relative_path: "f.bin".into(),
        size,
        chunk_size,
        chunk_hashes: vec![vec![7u8; 32]; hashes],
    };
    let manifest = |entry: SendFileEntry, total: u64| SendManifest {
        transfer_id: format!("bad-{}", entry.chunk_size),
        files: vec![entry],
        total_size: total,
        offered_at_unix_nanos: 0,
    };
    let mut bad_hash = entry(1024, 2048, 2);
    bad_hash.chunk_hashes[1] = vec![1u8; 5];
    let cases = [
        manifest(entry(u32::MAX, u64::from(u32::MAX), 1), u64::from(u32::MAX)),
        manifest(entry(0, 10, 1), 10),
        manifest(entry(1024, 2048, 3), 2048),
        manifest(bad_hash, 2048),
        manifest(entry(1024, 2048, 2), 1),
    ];
    for (n, case) in cases.into_iter().enumerate() {
        let (grant_id, nonce) = (format!("grant-{n}"), format!("nonce-{n}"));
        grants.issue(&grant_id, &nonce, dialer.key);
        let ack = raw_offer_manifest(&dialer, &acceptor, case, &grant_id, &nonce).await;
        assert!(!ack.accepted, "case {n} must be rejected");
        assert!(!ack.reason.is_empty());
    }
    assert!(service.list_inbox().unwrap().is_empty(), "a rejected manifest leaves no trace");

    grants.issue("grant-ok", "nonce-ok", dialer.key);
    let good = SendManifest {
        transfer_id: "good".into(),
        files: vec![entry(1024, 2048, 2)],
        total_size: 2048,
        offered_at_unix_nanos: 0,
    };
    let ack = raw_offer_manifest(&dialer, &acceptor, good, "grant-ok", "nonce-ok").await;
    assert!(ack.accepted, "a consistent manifest is still accepted: {}", ack.reason);
}

// ---- cancel and retry ----------------------------------------------------

/// `ReceiverWithResolvableSender` whose sender can be made unknown, standing
/// in for a sender that was removed from the account after the offer.
struct SwitchableDirectory {
    inner: ReceiverWithResolvableSender,
    sender_known: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl DeviceDirectory for SwitchableDirectory {
    fn resolve(&self, device_query: &str) -> Option<ResolvedDevice> {
        if self.sender_known.load(std::sync::atomic::Ordering::SeqCst) {
            self.inner.resolve(device_query)
        } else {
            None
        }
    }
    fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String> {
        self.inner.device_id_for_key(signing_key)
    }
    async fn consume_grant(
        &self,
        grant_id: &str,
        grant_nonce: &str,
        peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        self.inner.consume_grant(grant_id, grant_nonce, peer_key).await
    }
}

/// Where the next grant request parks: `(entered, proceed)`.
type GrantGate =
    Arc<std::sync::Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>>;

/// `GrantingDirectory` that can stop granting, or grant for a device that now has another key.
struct SwitchableGrants {
    inner: GrantingDirectory,
    available: Arc<std::sync::atomic::AtomicBool>,
    key_replaced: Arc<std::sync::atomic::AtomicBool>,
    /// The next grant request parks here: `(entered, proceed)`.
    gate: GrantGate,
}

#[async_trait::async_trait]
impl DeviceDirectory for SwitchableGrants {
    fn resolve(&self, device_query: &str) -> Option<ResolvedDevice> {
        self.inner.resolve(device_query)
    }
    fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String> {
        self.inner.device_id_for_key(signing_key)
    }
    async fn request_grant(&self, receiver_device_query: &str) -> Option<GrantedDevice> {
        let gate = self.gate.lock().unwrap().take();
        if let Some((entered, proceed)) = gate {
            entered.notify_one();
            proceed.notified().await;
        }
        if !self.available.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        let mut granted = self.inner.request_grant(receiver_device_query).await?;
        if self.key_replaced.load(std::sync::atomic::Ordering::SeqCst) {
            granted.device.signing_key = [9; 32];
        }
        Some(granted)
    }
}

struct OfferedPair {
    sender: Arc<SendService>,
    grants_available: Arc<std::sync::atomic::AtomicBool>,
    key_replaced: Arc<std::sync::atomic::AtomicBool>,
    grant_gate: GrantGate,
    source_path: PathBuf,
    receiver: Arc<SendService>,
    sender_known: Arc<std::sync::atomic::AtomicBool>,
    transfer_id: String,
    content: Vec<u8>,
    _guards: (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir),
    _endpoints: (Arc<TestEndpoint>, Arc<TestEndpoint>),
}

/// A sender that has offered one multi-chunk file to a receiver that has
/// accepted it, and has not yet received anything.
async fn offered_pair() -> OfferedPair {
    let sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;
    receiver_endpoint.admit(sender_endpoint.key);
    sender_endpoint.admit(receiver_endpoint.key);

    let grants = Arc::new(FakeGrantStore::default());
    let grants_available = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let key_replaced = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let grant_gate = Arc::new(std::sync::Mutex::new(None));
    let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(SwitchableGrants {
        inner: GrantingDirectory {
            sender_key: sender_endpoint.key,
            grants: grants.clone(),
            target: receiver_endpoint.resolved("receiver-device"),
        },
        available: grants_available.clone(),
        key_replaced: key_replaced.clone(),
        gate: grant_gate.clone(),
    });
    let (sender_service, sender_guard) = serving_service(&sender_endpoint, sender_directory);
    let sender_known = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let receiver_directory: Arc<dyn DeviceDirectory> = Arc::new(SwitchableDirectory {
        inner: ReceiverWithResolvableSender {
            sender: sender_endpoint.resolved("sender-device"),
            grants,
        },
        sender_known: sender_known.clone(),
    });
    let (receiver, receiver_guard) = serving_service(&receiver_endpoint, receiver_directory);

    let content: Vec<u8> = (0..400_000u32).map(|n| (n % 251) as u8).collect();
    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("big.bin");
    std::fs::write(&source_path, &content).unwrap();
    let offer = sender_service.offer_send(&source_path, "receiver-device").await.unwrap();
    OfferedPair {
        sender: sender_service,
        grants_available,
        key_replaced,
        grant_gate,
        source_path,
        receiver,
        sender_known,
        transfer_id: offer.transfer_id,
        content,
        _guards: (sender_guard, receiver_guard, source_dir),
        _endpoints: (sender_endpoint, receiver_endpoint),
    }
}

fn inbox_status(service: &SendService, transfer_id: &str) -> &'static str {
    service
        .list_inbox()
        .unwrap()
        .into_iter()
        .find(|e| e.transfer_id == transfer_id)
        .expect("listed")
        .status
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_is_idempotent_and_a_canceled_transfer_is_not_received() {
    let pair = offered_pair().await;
    pair.receiver.cancel_transfer(&pair.transfer_id).unwrap();
    pair.receiver.cancel_transfer(&pair.transfer_id).unwrap();
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "canceled");

    let error = pair.receiver.receive_transfer(&pair.transfer_id, None).await.unwrap_err();
    assert!(matches!(error, SendError::TransferCanceled(_)), "got {error:?}");
    assert!(matches!(
        pair.receiver.cancel_transfer("no-such-transfer"),
        Err(SendError::UnknownTransfer(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_stops_the_running_receive_and_retry_finishes_it() {
    let pair = offered_pair().await;
    let parked = pair.receiver.test_abort_after_n_chunks(1);
    let destination = tempfile::tempdir().unwrap();
    let dest_path = destination.path().join("out");

    let receiver = pair.receiver.clone();
    let id = pair.transfer_id.clone();
    let dest = dest_path.clone();
    let running = tokio::spawn(async move { receiver.receive_transfer(&id, Some(&dest)).await });
    tokio::time::timeout(Duration::from_secs(20), parked.notified())
        .await
        .expect("the receive must reach its first confirmed chunk");
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "in_progress");

    pair.receiver.cancel_transfer(&pair.transfer_id).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), running).await.unwrap().unwrap();
    assert!(matches!(result, Err(SendError::TransferCanceled(_))), "got {result:?}");
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "canceled");

    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        pair.receiver.retry_transfer(&pair.transfer_id),
    )
    .await
    .unwrap()
    .expect("retry resumes a canceled transfer");
    assert_eq!(outcome.destination_dir, dest_path, "retry keeps the recorded destination");
    assert_eq!(std::fs::read(dest_path.join("big.bin")).unwrap(), pair.content);
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_of_one_transfer_leaves_another_running_receive_alone() {
    let pair = offered_pair().await;
    let parked = pair.receiver.test_abort_after_n_chunks(1);
    let receiver = pair.receiver.clone();
    let id = pair.transfer_id.clone();
    let dest = tempfile::tempdir().unwrap();
    let dest_path = dest.path().join("out");
    let running =
        tokio::spawn(async move { receiver.receive_transfer(&id, Some(&dest_path)).await });
    tokio::time::timeout(Duration::from_secs(20), parked.notified()).await.unwrap();

    // Canceling an unrelated id neither errors for a known row nor stops this receive.
    assert!(pair.receiver.cancel_transfer("other").is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!running.is_finished(), "an unrelated cancel must not stop this receive");
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "in_progress");
    running.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_revalidates_before_changing_anything() {
    let pair = offered_pair().await;
    let destination = tempfile::tempdir().unwrap();
    let dest_path = destination.path().join("out");

    // Nothing to retry while it is still waiting to be received.
    let error = pair.receiver.retry_transfer(&pair.transfer_id).await.unwrap_err();
    assert!(matches!(error, SendError::NotRetryable { .. }), "got {error:?}");

    // Record a destination, then cancel.
    pair.receiver
        .store
        .claim_inbound_destination(&pair.transfer_id, dest_path.to_str().unwrap())
        .unwrap();
    pair.receiver.cancel_transfer(&pair.transfer_id).unwrap();

    // The sender is no longer a known device: retry refuses and the transfer stays canceled.
    pair.sender_known.store(false, std::sync::atomic::Ordering::SeqCst);
    let error = pair.receiver.retry_transfer(&pair.transfer_id).await.unwrap_err();
    assert!(matches!(error, SendError::NoKnownAddress(_)), "got {error:?}");
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "canceled");
    pair.sender_known.store(true, std::sync::atomic::Ordering::SeqCst);

    // The destination became a file: retry refuses and the transfer stays canceled.
    std::fs::write(&dest_path, b"in the way").unwrap();
    let error = pair.receiver.retry_transfer(&pair.transfer_id).await.unwrap_err();
    assert!(matches!(error, SendError::BadDestination(..)), "got {error:?}");
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "canceled");

    // Once the problems are gone retry succeeds.
    std::fs::remove_file(&dest_path).unwrap();
    pair.receiver.retry_transfer(&pair.transfer_id).await.unwrap();
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receive_that_errors_is_failed_not_in_progress() {
    let pair = offered_pair().await;
    pair.sender_known.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(pair.receiver.receive_transfer(&pair.transfer_id, None).await.is_err());
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "failed");

    // A failed transfer is retried the same way.
    pair.sender_known.store(true, std::sync::atomic::Ordering::SeqCst);
    pair.receiver.retry_transfer(&pair.transfer_id).await.unwrap();
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "completed");
}

// ---- the sender's side: cancel, retry, history -----------------------------------------

/// The sender hears that a transfer finished from the receiver, in the background.
async fn wait_for_sent_status(service: &SendService, transfer_id: &str, status: &str) {
    for _ in 0..200 {
        if sent_status(service, transfer_id).status == status {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the sent transfer never became {status}: {:?}", sent_status(service, transfer_id));
}

/// Tells `target` that `transfer_id` finished, as `dialer`.
async fn raw_done(dialer: &TestEndpoint, target: &TestEndpoint, transfer_id: &str) -> bool {
    let connection =
        dialer.node.connect_track_send(&target.resolved("target").address()).await.unwrap();
    let (mut send, mut recv) = connection.open_stream().await.unwrap();
    write_message(
        &mut send,
        &SendEnvelope {
            payload: Some(send_envelope::Payload::Done(yadorilink_ipc_proto::send::TransferDone {
                transfer_id: transfer_id.to_string(),
            })),
            grant_id: String::new(),
            grant_nonce: String::new(),
        },
    )
    .await
    .unwrap();
    send.finish().ok();
    let ack: SendManifestAck = read_message(&mut recv).await.unwrap();
    connection.close(close_code::DONE, b"test done");
    ack.accepted
}

fn sent_status(service: &SendService, transfer_id: &str) -> SentEntry {
    service.list_sent().unwrap().into_iter().find(|e| e.transfer_id == transfer_id).expect("listed")
}

fn inbox_failure(service: &SendService, transfer_id: &str) -> Option<String> {
    service.list_inbox().unwrap().into_iter().find(|e| e.transfer_id == transfer_id)?.failure
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sent_transfer_is_listed_and_a_receive_completes_it() {
    let pair = offered_pair().await;
    let entry = sent_status(&pair.sender, &pair.transfer_id);
    assert_eq!((entry.status, entry.can_retry), ("accepted", false));
    assert_eq!(entry.target_device_id, "receiver-device");
    assert_eq!(entry.files, vec![("big.bin".to_string(), pair.content.len() as u64)]);
    assert_eq!(
        pair.sender.transfer_direction(&pair.transfer_id).unwrap(),
        Some(TransferDirection::Sent)
    );
    assert_eq!(
        pair.receiver.transfer_direction(&pair.transfer_id).unwrap(),
        Some(TransferDirection::Received)
    );

    pair.receiver.receive_transfer(&pair.transfer_id, None).await.unwrap();
    wait_for_sent_status(&pair.sender, &pair.transfer_id, "completed").await;

    // Canceling a completed transfer is a no-op: it stays completed.
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "completed");
}

/// A receiver that already holds the content never pulls it, yet the sender still learns the
/// transfer finished: completion comes from the receiver saying so, not from counting pulls.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transfer_the_receiver_already_holds_still_completes_for_the_sender() {
    let pair = offered_pair().await;
    pair.receiver.receive_transfer(&pair.transfer_id, None).await.unwrap();
    wait_for_sent_status(&pair.sender, &pair.transfer_id, "completed").await;

    // The same bytes again, under another name: nothing needs pulling.
    let copy = pair.source_path.with_file_name("copy.bin");
    std::fs::write(&copy, &pair.content).unwrap();
    let second = pair.sender.offer_send(&copy, "receiver-device").await.unwrap();
    assert_ne!(second.transfer_id, pair.transfer_id);
    pair.receiver.receive_transfer(&second.transfer_id, None).await.unwrap();
    wait_for_sent_status(&pair.sender, &second.transfer_id, "completed").await;
}

/// Only the device a transfer was offered to can complete it, and a canceled one stays canceled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_receiver_can_complete_a_sent_transfer_and_a_cancel_is_not_undone() {
    let pair = offered_pair().await;
    let stranger = raw_endpoint().await;
    pair._endpoints.0.admit(stranger.key);
    assert!(
        !raw_done(&stranger, &pair._endpoints.0, &pair.transfer_id).await,
        "a device the transfer was not offered to cannot complete it"
    );
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "accepted");

    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    assert!(!raw_done(&pair._endpoints.1, &pair._endpoints.0, &pair.transfer_id).await);
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "canceled");
    assert!(
        pair.sender.expects_pull_from(&pair._endpoints.1.key),
        "the receiver is still admitted, to be told the transfer was canceled"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceling_a_sent_transfer_is_idempotent_and_refuses_the_pull() {
    let pair = offered_pair().await;
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    let entry = sent_status(&pair.sender, &pair.transfer_id);
    assert_eq!((entry.status, entry.can_retry), ("canceled", true));
    assert!(matches!(
        pair.sender.cancel_transfer("no-such-transfer"),
        Err(SendError::UnknownTransfer(_))
    ));

    let error = pair.receiver.receive_transfer(&pair.transfer_id, None).await.unwrap_err();
    assert!(matches!(&error, SendError::PullRejected(r) if r == PULL_REASON_CANCELED), "{error:?}");
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "failed");
    assert_eq!(
        inbox_failure(&pair.receiver, &pair.transfer_id).as_deref(),
        Some(crate::error::failure::SENDER_CANCELED)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retrying_a_canceled_sent_transfer_offers_it_again_and_the_receiver_can_finish() {
    let pair = offered_pair().await;
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    assert!(pair.receiver.receive_transfer(&pair.transfer_id, None).await.is_err());

    let outcome = pair.sender.retry_sent_transfer(&pair.transfer_id).await.unwrap();
    assert_eq!(outcome.transfer_id, pair.transfer_id, "the same transfer, not a new one");
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "accepted");

    // The receiver resumes it the way it resumes any failed transfer, and the failure note goes.
    pair.receiver.retry_transfer(&pair.transfer_id).await.unwrap();
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "completed");
    assert_eq!(inbox_failure(&pair.receiver, &pair.transfer_id), None);
    wait_for_sent_status(&pair.sender, &pair.transfer_id, "completed").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sent_transfer_is_retried_only_when_nothing_it_was_bound_to_changed() {
    let pair = offered_pair().await;
    // Still accepted: nothing to retry.
    let error = pair.sender.retry_sent_transfer(&pair.transfer_id).await.unwrap_err();
    assert!(matches!(error, SendError::NotRetryable { .. }), "got {error:?}");
    // A transfer this device received is not one it can retry as a sender.
    let error = pair.receiver.retry_sent_transfer(&pair.transfer_id).await.unwrap_err();
    assert!(matches!(error, SendError::NotSent(_)), "got {error:?}");

    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    // The offered file changed: the person sends it again to offer what is there now.
    let original = std::fs::read(&pair.source_path).unwrap();
    std::fs::write(&pair.source_path, b"edited after the offer").unwrap();
    let error = pair.sender.retry_sent_transfer(&pair.transfer_id).await.unwrap_err();
    assert!(matches!(error, SendError::SourceChanged(_)), "got {error:?}");
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "canceled");
    // Checking the edited file stored none of it: nothing was sent, so nothing is kept.
    let edited = hash_block_bytes(b"edited after the offer");
    assert_eq!(pair.sender.block_store.present_blocks(&[edited]).unwrap(), vec![false]);

    // The offered file is gone.
    std::fs::remove_file(&pair.source_path).unwrap();
    let error = pair.sender.retry_sent_transfer(&pair.transfer_id).await.unwrap_err();
    assert!(matches!(error, SendError::SourceChanged(_)), "got {error:?}");
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "canceled");

    // Back as it was: the retry goes through.
    std::fs::write(&pair.source_path, original).unwrap();
    pair.sender.retry_sent_transfer(&pair.transfer_id).await.unwrap();
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "accepted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retry_needs_a_new_authorization_and_never_extends_an_old_one() {
    let pair = offered_pair().await;
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();

    // No new authorization can be had: the retry says so and changes nothing.
    pair.grants_available.store(false, std::sync::atomic::Ordering::SeqCst);
    let error = pair.sender.retry_sent_transfer(&pair.transfer_id).await.unwrap_err();
    assert!(matches!(error, SendError::NeedsNewAuthorization(_)), "got {error:?}");
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "canceled");

    // The device now has another key: it is not the one the transfer was offered to.
    pair.grants_available.store(true, std::sync::atomic::Ordering::SeqCst);
    pair.key_replaced.store(true, std::sync::atomic::Ordering::SeqCst);
    let error = pair.sender.retry_sent_transfer(&pair.transfer_id).await.unwrap_err();
    assert!(matches!(error, SendError::TargetChanged(..)), "got {error:?}");
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "canceled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_history_of_finished_sent_transfers_is_bounded() {
    let (store, _dir) = {
        let dir = tempfile::tempdir().unwrap();
        (SendStore::open(dir.path().join("s.sqlite3")).unwrap(), dir)
    };
    let manifest = |id: &str| SendManifest {
        transfer_id: id.into(),
        files: vec![],
        total_size: 0,
        offered_at_unix_nanos: 0,
    };
    for n in 0..130i64 {
        let id = format!("t{n:03}");
        store.insert_outbound_offered(&id, "d", &[1; 32], "/s", &manifest(&id), n).unwrap();
        store.cancel_outbound(&id).unwrap();
        store.record_failure(&id, "interrupted").unwrap();
    }
    store.insert_outbound_offered("live", "d", &[1; 32], "/s2", &manifest("live"), 1000).unwrap();
    store.prune_finished(FINISHED_RETAINED_LIMIT, "").unwrap();

    let kept = store.list_outbound_recent(usize::MAX >> 1).unwrap();
    assert_eq!(kept.len(), FINISHED_RETAINED_LIMIT + 1, "100 finished and the live one");
    assert!(store.get_outbound("t000").unwrap().is_none(), "the oldest went");
    assert!(store.failure("t000").unwrap().is_none(), "and its note with it");
    assert!(store.get_outbound("t129").unwrap().is_some());
    assert!(store.get_outbound("live").unwrap().is_some(), "a live transfer is never pruned");
    // The list shows fewer than are kept.
    assert_eq!(store.list_outbound_recent(FINISHED_HISTORY_LIMIT).unwrap().len(), 21);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_while_a_pull_is_being_served_stops_it_at_a_chunk_boundary() {
    let pair = offered_pair().await;
    let (reached, proceed) = pair.sender.test_park_next_serve();
    let receiver = pair.receiver.clone();
    let id = pair.transfer_id.clone();
    let receiving = tokio::spawn(async move { receiver.receive_transfer(&id, None).await });
    tokio::time::timeout(Duration::from_secs(20), reached.notified())
        .await
        .expect("the sender must admit the pull and reach its first chunk");

    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    proceed.notify_one();

    let result = tokio::time::timeout(Duration::from_secs(20), receiving).await.unwrap().unwrap();
    // The rejection arrives as a whole message, so the receiver reads it as the sender's cancel,
    // not as a corrupt chunk.
    assert!(
        matches!(&result, Err(SendError::PullRejected(r)) if r == PULL_REASON_CANCELED),
        "got {result:?}"
    );
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "canceled");
    assert_eq!(
        inbox_failure(&pair.receiver, &pair.transfer_id).as_deref(),
        Some(crate::error::failure::SENDER_CANCELED)
    );
}

/// A receiver that stops reading must not hold the serve (and so a cancel) for as long as the
/// connection lives: the write gives up, the sender keeps why, and the receiver can fetch again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receiver_that_stops_reading_ends_the_serve_and_the_sender_keeps_why() {
    let pair = offered_pair().await;
    pair.sender.test_set_serve_write_timeout(Duration::from_millis(300));
    pair.sender.test_stall_next_serve_write();

    let first = tokio::time::timeout(
        Duration::from_secs(20),
        pair.receiver.receive_transfer(&pair.transfer_id, None),
    )
    .await
    .expect("the serve must end, not outlast the connection");
    assert!(first.is_err(), "the receiver is cut off: {first:?}");

    let entry = sent_status(&pair.sender, &pair.transfer_id);
    assert_eq!(entry.status, "accepted", "the offer is still the receiver's to fetch");
    assert_eq!(entry.failure.as_deref(), Some(crate::error::failure::STALLED));

    // The receiver fetches again; once a whole file is served the note no longer holds.
    pair.receiver.receive_transfer(&pair.transfer_id, None).await.unwrap();
    let entry = sent_status(&pair.sender, &pair.transfer_id);
    assert_eq!(entry.failure, None, "a served-through pull clears the stall");
}

/// Negative control: a receiver that reads leaves no stall note.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receiver_that_keeps_reading_leaves_no_stall_note() {
    let pair = offered_pair().await;
    pair.sender.test_set_serve_write_timeout(Duration::from_millis(300));
    pair.receiver.receive_transfer(&pair.transfer_id, None).await.unwrap();
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).failure, None);
}

/// A serve that ends after the sender canceled must not write a stall over the cancel's record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_serve_ending_after_a_cancel_does_not_record_a_stall() {
    let pair = offered_pair().await;
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    pair.sender.note_serve_outcome(&pair.transfer_id, &Err(SendError::ReceiverStalled));
    let entry = sent_status(&pair.sender, &pair.transfer_id);
    assert_eq!(entry.status, "canceled");
    assert_eq!(entry.failure, None);
}

/// The bound is on inactivity, not on the whole chunk: a slow receiver that keeps reading is
/// served even when the chunk takes far longer than the bound.
#[tokio::test]
async fn a_slow_receiver_that_keeps_reading_is_not_cut_off() {
    let header = ChunkStreamMessage {
        payload: Some(chunk_stream_message::Payload::Header(ChunkHeader {
            chunk_index: 0,
            size: 512 * 1024,
            last_chunk: true,
        })),
    };
    let body = vec![7u8; 512 * 1024];
    let (mut writer, mut reader) = tokio::io::duplex(16 * 1024);
    let drain = tokio::spawn(async move {
        let mut total = 0usize;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await.unwrap();
            if n == 0 {
                return total;
            }
            total += n;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    let started = std::time::Instant::now();
    write_chunk_bounded(&mut writer, &header, &body, Duration::from_millis(100), false)
        .await
        .unwrap();
    assert!(started.elapsed() > Duration::from_millis(400), "the chunk outlasts the bound");
    drop(writer);
    assert!(drain.await.unwrap() >= body.len());
}

/// The write bound is real flow-control backpressure: a peer that never reads blocks a chunk
/// larger than the pipe, and the bound ends it; one that reads is served whole.
#[tokio::test]
async fn a_chunk_write_to_a_peer_that_never_reads_is_bounded() {
    let header = ChunkStreamMessage {
        payload: Some(chunk_stream_message::Payload::Header(ChunkHeader {
            chunk_index: 0,
            size: 1 << 20,
            last_chunk: true,
        })),
    };
    let body = vec![7u8; 1 << 20];

    let (mut writer, _unread) = tokio::io::duplex(1024);
    let result =
        write_chunk_bounded(&mut writer, &header, &body, Duration::from_millis(100), false).await;
    assert!(matches!(result, Err(SendError::ReceiverStalled)), "got {result:?}");

    let (mut writer, mut reader) = tokio::io::duplex(1024);
    let drain = tokio::spawn(async move {
        let mut sink = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut sink).await.unwrap();
        sink.len()
    });
    write_chunk_bounded(&mut writer, &header, &body, Duration::from_secs(20), false).await.unwrap();
    drop(writer);
    assert!(drain.await.unwrap() >= body.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offering_the_same_file_again_while_it_is_accepted_is_the_same_offer() {
    let pair = offered_pair().await;
    let again = pair.sender.offer_send(&pair.source_path, "receiver-device").await.unwrap();
    assert_eq!(again.transfer_id, pair.transfer_id);
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "accepted");
}

/// Canceling counts toward the bound too: a device that keeps sending and canceling never keeps
/// more than the newest finished transfers of each direction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceling_keeps_the_finished_history_within_its_bound() {
    let pair = offered_pair().await;
    let manifest = |id: &str| SendManifest {
        transfer_id: id.into(),
        files: vec![],
        total_size: 0,
        offered_at_unix_nanos: 0,
    };
    for n in 0..(FINISHED_RETAINED_LIMIT as i64 + 30) {
        let id = format!("old-{n:03}");
        pair.sender
            .store
            .insert_outbound_offered(&id, "d", &[1; 32], "/s", &manifest(&id), -1000 + n)
            .unwrap();
        pair.sender.store.cancel_outbound(&id).unwrap();
        pair.receiver
            .store
            .insert_inbound_if_new(&format!("in-{n:03}"), "s", &manifest("x"), -1000 + n)
            .unwrap();
        pair.receiver.store.cancel_inbound(&format!("in-{n:03}")).unwrap();
    }
    // Through the service, as a person does.
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    pair.receiver.cancel_transfer(&pair.transfer_id).unwrap();

    let finished = |sent: &[SentEntry]| sent.iter().filter(|e| e.status == "canceled").count();
    assert_eq!(finished(&pair.sender.list_sent().unwrap()), FINISHED_HISTORY_LIMIT);
    assert_eq!(
        pair.sender.store.list_outbound_recent(usize::MAX >> 1).unwrap().len(),
        FINISHED_RETAINED_LIMIT,
        "older finished transfers are deleted, not just hidden"
    );
    assert_eq!(
        pair.receiver
            .store
            .list_inbound_recent(usize::MAX >> 1)
            .unwrap()
            .iter()
            .filter(|t| t.status == InboundStatus::Canceled)
            .count(),
        FINISHED_RETAINED_LIMIT
    );
}

/// A transfer older than the bound that is canceled still shows as canceled and can be retried:
/// pruning spares it this once, and the pull being served for it stops either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceling_an_old_transfer_does_not_make_it_vanish() {
    let pair = offered_pair().await;
    let manifest = |id: &str| SendManifest {
        transfer_id: id.into(),
        files: vec![],
        total_size: 0,
        offered_at_unix_nanos: 0,
    };
    for n in 0..(FINISHED_RETAINED_LIMIT as i64 + 5) {
        let id = format!("new-{n:03}");
        pair.sender
            .store
            .insert_outbound_offered(&id, "d", &[1; 32], "/s", &manifest(&id), i64::MAX / 2 + n)
            .unwrap();
        pair.sender.store.cancel_outbound(&id).unwrap();
    }
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    // Older than every kept one, so not among the listed ones, but still on record.
    assert_eq!(
        pair.sender.store.get_outbound(&pair.transfer_id).unwrap().map(|o| o.status),
        Some(OutboundStatus::Canceled)
    );
    pair.sender.retry_sent_transfer(&pair.transfer_id).await.unwrap();
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "accepted");
}

/// A cancel that lands while a retry waits for its new authorization is newer than the retry and
/// stands, whatever state the transfer was in when the retry began.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_during_a_retry_is_not_undone_by_it() {
    for from_canceled in [false, true] {
        let pair = offered_pair().await;
        // The retry starts from a canceled transfer, or from one never answered ("offered").
        pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
        if !from_canceled {
            pair.sender
                .store
                .reopen_outbound(&pair.transfer_id, &OutboundStatus::Canceled)
                .unwrap();
        }
        let entered = Arc::new(tokio::sync::Notify::new());
        let proceed = Arc::new(tokio::sync::Notify::new());
        *pair.grant_gate.lock().unwrap() = Some((entered.clone(), proceed.clone()));

        let sender = pair.sender.clone();
        let id = pair.transfer_id.clone();
        let retrying = tokio::spawn(async move { sender.retry_sent_transfer(&id).await });
        tokio::time::timeout(Duration::from_secs(10), entered.notified()).await.unwrap();
        // The person cancels while the retry waits for its grant.
        pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
        proceed.notify_one();

        let result = retrying.await.unwrap();
        assert!(matches!(result, Err(SendError::NotRetryable { .. })), "got {result:?}");
        assert_eq!(
            pair.sender.store.outbound_status(&pair.transfer_id).unwrap(),
            Some(OutboundStatus::Canceled),
            "from_canceled={from_canceled}"
        );
    }
}

/// The receiver can finish, and say so, before the sender has recorded the acceptance it is still
/// reading (an empty file, or content the receiver already holds): the transfer still completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completion_that_beats_the_acceptance_still_completes_the_transfer() {
    let pair = offered_pair().await;
    // Back to the moment before the acceptance was recorded.
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    pair.sender.store.reopen_outbound(&pair.transfer_id, &OutboundStatus::Canceled).unwrap();
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "offered");

    assert!(raw_done(&pair._endpoints.1, &pair._endpoints.0, &pair.transfer_id).await);
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "completed");
    // The acceptance arriving afterwards does not take it back.
    assert!(!pair.sender.store.mark_outbound_acked(&pair.transfer_id).unwrap());
    assert_eq!(sent_status(&pair.sender, &pair.transfer_id).status, "completed");
}

// ---- reaping blocks ------------------------------------------------------------------------

/// The hex hashes of every chunk of a transfer this service sent.
fn sent_chunks(service: &SendService, transfer_id: &str) -> Vec<String> {
    let outbound = service.store.get_outbound(transfer_id).unwrap().unwrap();
    outbound.manifest.files.iter().flat_map(|f| f.chunk_hashes.iter().map(hex::encode)).collect()
}

fn all_present(service: &SendService, hashes: &[String]) -> bool {
    hashes.iter().all(|h| bs_exists(&service.block_store, h))
}

fn none_present(service: &SendService, hashes: &[String]) -> bool {
    hashes.iter().all(|h| !bs_exists(&service.block_store, h))
}

fn bs_exists(store: &SegmentBlockStore, hash: &str) -> bool {
    yadorilink_local_storage::BlockStore::exists(store, hash).unwrap()
}

fn bs_put(store: &SegmentBlockStore, data: &[u8]) -> String {
    yadorilink_local_storage::BlockStore::put(store, data).unwrap()
}

fn old() -> std::time::SystemTime {
    std::time::SystemTime::now() - Duration::from_secs(3 * 24 * 60 * 60)
}

/// A block no transfer references goes once it is past the grace, and not before it: an offer
/// writes its blocks before its transfer is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreferenced_block_is_reaped_only_after_the_grace() {
    let pair = offered_pair().await;
    let stray = bs_put(&pair.sender.block_store, b"never offered");
    pair.sender.reap_blocks(BLOCK_REAP_GRACE).unwrap();
    assert!(bs_exists(&pair.sender.block_store, &stray), "a fresh block stays");

    pair.sender.block_store.backdate_block_for_tests(&stray, old()).unwrap();
    pair.sender.reap_blocks(BLOCK_REAP_GRACE).unwrap();
    assert!(!bs_exists(&pair.sender.block_store, &stray), "an old unreferenced block goes");
}

/// Everything a sent transfer on record can serve or retry keeps its blocks, in every state
/// (negative control: with no grace at all, nothing it needs is reaped).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocks_of_a_sent_transfer_on_record_are_never_reaped() {
    let pair = offered_pair().await;
    let chunks = sent_chunks(&pair.sender, &pair.transfer_id);
    assert!(chunks.len() > 1);
    let stray = bs_put(&pair.sender.block_store, b"stray");

    // Accepted.
    pair.sender.reap_blocks(Duration::ZERO).unwrap();
    assert!(all_present(&pair.sender, &chunks), "accepted");
    assert!(!bs_exists(&pair.sender.block_store, &stray), "the control does reap");

    // Canceled: retryable, and a retry stores no content.
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    pair.sender.reap_blocks(Duration::ZERO).unwrap();
    assert!(all_present(&pair.sender, &chunks), "canceled");
    pair.sender.retry_sent_transfer(&pair.transfer_id).await.unwrap();
    pair.sender.reap_blocks(Duration::ZERO).unwrap();

    // The receiver still gets every chunk, and the completed transfer keeps serving.
    pair.receiver.receive_transfer(&pair.transfer_id, None).await.unwrap();
    wait_for_sent_status(&pair.sender, &pair.transfer_id, "completed").await;
    pair.sender.reap_blocks(Duration::ZERO).unwrap();
    assert!(all_present(&pair.sender, &chunks), "completed");
}

/// Received blocks: a finished receive no longer needs them, one that can still resume does, and
/// the received files are untouched either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn received_blocks_go_when_the_receive_completes_and_stay_while_it_can_resume() {
    let pair = offered_pair().await;
    let chunks = sent_chunks(&pair.sender, &pair.transfer_id);

    // Pending (offered, nothing pulled) and canceled (retryable) keep what they hold.
    pair.receiver.reap_blocks(Duration::ZERO).unwrap();
    pair.receiver.cancel_transfer(&pair.transfer_id).unwrap();
    pair.receiver.reap_blocks(Duration::ZERO).unwrap();
    let outcome = pair.receiver.retry_transfer(&pair.transfer_id).await.unwrap();
    assert!(all_present(&pair.receiver, &chunks), "pulled blocks stay until the receive is done");
    assert_eq!(inbox_status(&pair.receiver, &pair.transfer_id), "completed");

    pair.receiver.reap_blocks(Duration::ZERO).unwrap();
    assert!(none_present(&pair.receiver, &chunks), "a completed receive keeps no blocks");
    let written = std::fs::read(outcome.destination_dir.join("big.bin")).unwrap();
    assert_eq!(written, pair.content, "the received file is untouched");
    // The sender's copy, still serving, is unaffected.
    pair.sender.reap_blocks(Duration::ZERO).unwrap();
    assert!(all_present(&pair.sender, &chunks));
}

/// Content two transfers share stays while either of them is on record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_shared_by_two_transfers_stays_until_both_are_gone() {
    let pair = offered_pair().await;
    let chunks = sent_chunks(&pair.sender, &pair.transfer_id);
    let original = pair.sender.store.get_outbound(&pair.transfer_id).unwrap().unwrap();
    let mut manifest = original.manifest.clone();
    manifest.transfer_id = "twin".into();
    pair.sender
        .store
        .insert_outbound_offered("twin", "d", &[1; 32], "/twin", &manifest, 5)
        .unwrap();
    for hash in &chunks {
        pair.sender.block_store.backdate_block_for_tests(hash, old()).unwrap();
    }

    // Push the original out of the bounded history; the twin still references the blocks.
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();
    pair.sender.store.cancel_outbound("twin").unwrap();
    pair.sender.store.delete_outbound_for_tests(&pair.transfer_id);
    pair.sender.reap_blocks(BLOCK_REAP_GRACE).unwrap();
    assert!(all_present(&pair.sender, &chunks), "the twin still needs them");

    pair.sender.store.delete_outbound_for_tests("twin");
    pair.sender.reap_blocks(BLOCK_REAP_GRACE).unwrap();
    assert!(none_present(&pair.sender, &chunks), "nothing needs them now");
}

/// A transfer pushed out of the bounded history takes its blocks with it, through the service's
/// own pruning; the ones inside the bound keep theirs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pruning_a_finished_transfer_reaps_its_blocks() {
    let pair = offered_pair().await;
    let mut kept_probe = Vec::new();
    for n in 0..(FINISHED_RETAINED_LIMIT as i64 + 5) {
        let id = format!("old-{n:03}");
        let hash = bs_put(&pair.sender.block_store, format!("content {n}").as_bytes());
        pair.sender.block_store.backdate_block_for_tests(&hash, old()).unwrap();
        let manifest = SendManifest {
            transfer_id: id.clone(),
            files: vec![SendFileEntry {
                relative_path: "f".into(),
                size: 1,
                chunk_size: 1,
                chunk_hashes: vec![hex::decode(&hash).unwrap()],
            }],
            total_size: 1,
            offered_at_unix_nanos: 0,
        };
        pair.sender
            .store
            .insert_outbound_offered(&id, "d", &[1; 32], "/s", &manifest, -1000 + n)
            .unwrap();
        pair.sender.store.cancel_outbound(&id).unwrap();
        kept_probe.push(hash);
    }
    let live = sent_chunks(&pair.sender, &pair.transfer_id);
    pair.sender.cancel_transfer(&pair.transfer_id).unwrap();

    assert!(none_present(&pair.sender, &kept_probe[..6]), "the six oldest were pruned");
    assert!(all_present(&pair.sender, &kept_probe[6..]), "the rest are inside the bound");
    assert!(all_present(&pair.sender, &live), "the canceled transfer is retryable");
}
