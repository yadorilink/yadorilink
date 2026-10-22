//! A real substrate endpoint for a test that builds its own peer sessions.
//!
//! A `PeerSyncSession` requires transports; the daemon supplies them from a
//! `SyncStack`, and a test below the daemon needs the same thing from
//! something smaller. What it must not be is a null transport: a session that
//! exists and can never carry anything is exactly the state this cutover
//! removes from production, and reintroducing it under a test-only name would
//! leave every later constructor and lifecycle change unchecked by the tests
//! meant to check it.
//!
//! So this is a real iroh endpoint, real lanes, and the same adapters
//! production uses. What it leaves out is everything above the transport:
//! there is no netmap here, so a peer is addressed by whatever address the
//! test registered for it, and authorization is the session's own business
//! exactly as in production.
//!
//! Not dialling is fine. A test whose subject never fetches a block simply
//! never opens a block lane — "unused" and "unusable" are different, and only
//! the second is what production had to stop being able to represent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_sync_substrate::{
    Lane, NetworkConfig, PeerAddress, PeerId, PeerLink, SubstrateNode,
};
use yadorilink_transport::TransportError;

use crate::block_lane::LaneBlockStream;
use crate::peer_transports::{PeerLinkSource, PeerTransports};
use crate::service_lane::LaneServiceStream;

/// Where every test node in this process can be reached.
///
/// A stand-in for the netmap, and deliberately only that: it answers "what is
/// this device's address", never "may it do anything".
#[derive(Clone, Default)]
pub struct TestAddressBook {
    entries: Arc<Mutex<HashMap<String, PeerAddress>>>,
    /// The same knowledge keyed the way the substrate asks for it.
    ///
    /// Nodes are dialled by endpoint id now, so `address_of` alone is no
    /// longer enough to reach one: something has to answer "where does this
    /// endpoint answer". This is that, and it is the same book so a test
    /// cannot populate one and forget the other.
    directory: yadorilink_sync_substrate::testing::SharedAddressBook,
}

impl TestAddressBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// The endpoint directory backing this book, for handing to a
    /// `NetworkConfig`.
    pub fn directory(&self) -> yadorilink_sync_substrate::testing::SharedAddressBook {
        self.directory.clone()
    }

    pub fn publish(&self, device_id: &str, address: PeerAddress) {
        use yadorilink_sync_substrate::AddressDirectory as _;
        self.directory.publish(
            address.peer(),
            address.direct_addrs().copied().collect(),
            address.relay_urls().map(ToString::to_string).collect(),
        );
        self.entries.lock().expect("address book poisoned").insert(device_id.to_string(), address);
    }

    pub fn address_of(&self, device_id: &str) -> Option<PeerAddress> {
        self.entries.lock().expect("address book poisoned").get(device_id).cloned()
    }
}

/// One device's substrate endpoint, plus the sessions it serves.
pub struct TestPeerNode {
    node: SubstrateNode,
    device_id: String,
    book: TestAddressBook,
    /// Sessions by the endpoint identity of the peer they talk to, so an
    /// inbound stream can be handed to the one that owns that peer.
    sessions: Arc<Mutex<HashMap<PeerId, Arc<PeerSyncSession>>>>,
    links: Arc<tokio::sync::Mutex<HashMap<String, Arc<PeerLink>>>>,
    /// Inbound lanes nobody is registered to serve.
    ///
    /// A test that plays the peer itself — answering a block request with
    /// something deliberately wrong, to state what the requester does about
    /// it — takes them from here. Not a second transport: the same lane, read
    /// by the test instead of by a session.
    unclaimed: tokio::sync::mpsc::UnboundedSender<(String, yadorilink_sync_substrate::LaneStream)>,
    unclaimed_rx: tokio::sync::Mutex<
        tokio::sync::mpsc::UnboundedReceiver<(String, yadorilink_sync_substrate::LaneStream)>,
    >,
}

impl TestPeerNode {
    /// Starts an endpoint for `device_id` and publishes its address.
    pub async fn start(device_id: &str, book: TestAddressBook) -> Arc<Self> {
        Self::start_with_config(device_id, book, NetworkConfig::direct_only()).await
    }

    /// Starts an endpoint for `device_id` with a caller-chosen `NetworkConfig`
    /// and publishes its address.
    ///
    /// The plain `start` above is the common case (direct loopback,
    /// no relay involved); this is for a test that needs the underlying
    /// substrate connection to be relay-only or relay-capable -- for
    /// example, one asserting that a session's block lane actually rides an
    /// in-process relay rather than merely converging.
    pub async fn start_with_config(
        device_id: &str,
        book: TestAddressBook,
        config: NetworkConfig,
    ) -> Arc<Self> {
        Self::start_with_key(device_id, book, config, iroh::SecretKey::generate()).await
    }

    /// Starts an endpoint whose every datagram is carried by `network` rather
    /// than by an operating-system socket.
    ///
    /// This is the whole of what a deterministic simulation has to change to
    /// run the substrate. Above the carrier, nothing differs from
    /// [`start`]: the same iroh endpoint with the same QUIC, TLS and stream
    /// multiplexing, the same `PeerLink`, the same [`PeerTransports`], and
    /// the same lane streams a session opens on them. A block that crosses
    /// one of those lanes here is real bytes over real QUIC; it simply never
    /// reaches a socket.
    ///
    /// The key is generated here rather than inside, because `network`
    /// identifies an endpoint by the public half and has to have a carrier
    /// registered for it before the endpoint binds and starts sending.
    ///
    /// [`start`]: Self::start
    pub async fn start_simulated(
        device_id: &str,
        book: TestAddressBook,
        network: &iroh::test_utils::test_transport::TestNetwork,
    ) -> Arc<Self> {
        Self::start_simulated_with_lookup(device_id, book, network, true).await
    }

    /// [`start_simulated`], with the option of leaving out the address lookup
    /// that makes the simulated carrier reachable.
    ///
    /// `false` exists for one purpose: a negative control. Everything else
    /// about the node is identical, so a test that connects with the lookup
    /// and fails to connect without it has shown that the traffic rode the
    /// simulated carrier and not some other path that happened to work.
    /// Without that pairing, a green lane test is consistent with the
    /// endpoints having quietly reached each other over the host's network.
    ///
    /// [`start_simulated`]: Self::start_simulated
    pub async fn start_simulated_with_lookup(
        device_id: &str,
        book: TestAddressBook,
        network: &iroh::test_utils::test_transport::TestNetwork,
        with_address_lookup: bool,
    ) -> Arc<Self> {
        let secret = iroh::SecretKey::generate();
        let transport = network
            .create_transport(secret.public())
            .expect("a simulated endpoint id must be unique within one network");
        let mut config = NetworkConfig::over_custom_transport(transport);
        if with_address_lookup {
            // Upstream's own lookup for upstream's own address kind. This
            // crate reimplements neither.
            config = config.with_address_lookup_override(Arc::new(network.address_lookup()));
        }
        Self::start_with_key(device_id, book, config, secret).await
    }

    /// [`start_simulated`], with every datagram passing through `faults`
    /// first.
    ///
    /// The wrapper sits between iroh and upstream's transport and nowhere
    /// else, so a session, its lanes and `PeerTransports` are identical to
    /// the unfaulted case. Returns the endpoint identity alongside the node,
    /// because a fault is declared between two endpoints and the caller
    /// cannot otherwise name them.
    ///
    /// [`start_simulated`]: Self::start_simulated
    pub async fn start_simulated_with_faults(
        device_id: &str,
        book: TestAddressBook,
        network: &iroh::test_utils::test_transport::TestNetwork,
        faults: &crate::sim_fault::SimFaultController,
    ) -> (Arc<Self>, iroh::EndpointId) {
        let secret = iroh::SecretKey::generate();
        let endpoint_id = secret.public();
        let node =
            Self::start_simulated_with_identity(device_id, book, network, faults, secret).await;
        (node, endpoint_id)
    }

    /// [`start_simulated_with_faults`], with the identity supplied by the
    /// caller rather than generated here.
    ///
    /// For a scenario that has to know which endpoint a device *will* be
    /// before that device exists. A fault schedule names devices by index and
    /// the carrier names them by `EndpointId`, so the mapping between the two
    /// has to be fixed before any host starts -- otherwise the scenario is
    /// assembling its fault targets from nodes that are already running, and
    /// a fault scheduled at offset zero has nothing to act on.
    ///
    /// The key, not the identity: the identity is `secret_key.public()` and
    /// is derived here rather than passed alongside. Taking both would invite
    /// a registry pairing one with the other, and a registry that can be
    /// wrong is a registry that will be.
    ///
    /// A restart keeps its identity by being started again with the same
    /// key, which is also what a real device does.
    ///
    /// [`start_simulated_with_faults`]: Self::start_simulated_with_faults
    pub async fn start_simulated_with_identity(
        device_id: &str,
        book: TestAddressBook,
        network: &iroh::test_utils::test_transport::TestNetwork,
        faults: &crate::sim_fault::SimFaultController,
        secret_key: iroh::SecretKey,
    ) -> Arc<Self> {
        let transport = faults
            .transport_for(network, secret_key.public())
            .expect("a simulated endpoint id must be unique within one network");
        let config = NetworkConfig::over_custom_transport(transport)
            .with_address_lookup_override(Arc::new(network.address_lookup()));
        Self::start_with_key(device_id, book, config, secret_key).await
    }

    async fn start_with_key(
        device_id: &str,
        book: TestAddressBook,
        config: NetworkConfig,
        secret_key: iroh::SecretKey,
    ) -> Arc<Self> {
        let (node, inbound) = SubstrateNode::spawn(
            secret_key,
            config.with_directory(Arc::new(book.directory())),
            std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
        )
        .await
        .expect("a test substrate endpoint must start");
        book.publish(device_id, node.local_address());

        let (unclaimed, unclaimed_rx) = tokio::sync::mpsc::unbounded_channel();
        let this = Arc::new(Self {
            node,
            device_id: device_id.to_string(),
            book,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            links: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            unclaimed,
            unclaimed_rx: tokio::sync::Mutex::new(unclaimed_rx),
        });
        this.clone().serve(inbound);
        this
    }

    /// The transports a session for `peer_device_id` reaches its peer with.
    pub fn transports_for(self: &Arc<Self>, peer_device_id: &str) -> Arc<PeerTransports> {
        Arc::new(PeerTransports::new(Arc::new(TestLink {
            node: self.clone(),
            device_id: peer_device_id.to_string(),
        })))
    }

    /// The connection to `peer_device_id`, dialled if there is not a live
    /// one, and cached exactly as [`transports_for`]'s own [`PeerLinkSource`]
    /// caches it -- calling both for the same peer yields the same
    /// underlying link. Exposed so a test can inspect what carrier a
    /// session's lanes are actually riding (`PeerLink::carrier`,
    /// `PeerLink::has_direct_path`), the same way production's
    /// `SyncStack::link_to` lets the daemon do it.
    ///
    /// [`transports_for`]: Self::transports_for
    pub async fn link_to(self: &Arc<Self>, peer_device_id: &str) -> Arc<PeerLink> {
        TestLink { node: self.clone(), device_id: peer_device_id.to_string() }
            .link()
            .await
            .expect("test peer link must connect")
    }

    /// Serve inbound streams from `peer_device_id` with `session`.
    ///
    /// Keyed by endpoint identity because that is what an inbound connection
    /// carries; the address book is what relates the two, standing in for the
    /// netmap's own device-to-key binding.
    pub fn serve_with(&self, peer_device_id: &str, session: Arc<PeerSyncSession>) {
        let Some(address) = self.book.address_of(peer_device_id) else {
            return;
        };
        self.sessions.lock().expect("sessions poisoned").insert(address.peer(), session);
    }

    /// The next inbound lane no registered session claimed.
    pub async fn accept_unclaimed_lane(
        &self,
    ) -> Option<(String, yadorilink_sync_substrate::LaneStream)> {
        self.unclaimed_rx.lock().await.recv().await
    }

    pub fn address(&self) -> PeerAddress {
        self.node.local_address()
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Routes every lane `link` opens to the session serving its peer, or to
    /// `unclaimed` when none does.
    async fn serve_link(self: Arc<Self>, link: PeerLink) {
        let peer = link.peer();
        while let Ok(mut stream) = link.accept_lane().await {
            let Ok(group) = yadorilink_sync_protocol::session::accept_lane(&mut stream).await
            else {
                continue;
            };
            let session = self.sessions.lock().expect("sessions poisoned").get(&peer).cloned();
            let Some(session) = session else {
                // Nobody here serves this peer, so a test is playing it. See
                // `unclaimed`.
                let _ = self.unclaimed.send((group.as_str().to_string(), stream));
                continue;
            };
            tokio::spawn(serve_lane(session, group, stream));
        }
    }

    fn serve(self: Arc<Self>, mut inbound: tokio::sync::mpsc::Receiver<PeerLink>) {
        tokio::spawn(async move {
            while let Some(link) = inbound.recv().await {
                tokio::spawn(self.clone().serve_link(link));
            }
        });
    }
}

/// Hands one accepted lane to the session serving its peer.
async fn serve_lane(
    session: Arc<PeerSyncSession>,
    group: yadorilink_sync_protocol::GroupId,
    stream: yadorilink_sync_substrate::LaneStream,
) {
    match stream.lane() {
        Lane::Block => session.serve_block_stream(Box::new(LaneBlockStream::new(stream))).await,
        Lane::Service => {
            session
                .serve_service_stream(group.as_str(), Box::new(LaneServiceStream::new(stream)))
                .await
        }
    }
}

struct TestLink {
    node: Arc<TestPeerNode>,
    device_id: String,
}

#[async_trait::async_trait]
impl PeerLinkSource for TestLink {
    async fn link(&self) -> Result<Arc<PeerLink>, TransportError> {
        let mut links = self.node.links.lock().await;
        if let Some(link) = links.get(&self.device_id) {
            if link.is_alive() {
                return Ok(link.clone());
            }
            links.remove(&self.device_id);
        }
        let address =
            self.node.book.address_of(&self.device_id).ok_or_else(|| {
                TransportError::NoRoute(format!("no address for {}", self.device_id))
            })?;
        let link = Arc::new(
            self.node
                .node
                .connect(address.peer())
                .await
                .map_err(|error| TransportError::NoRoute(error.to_string()))?,
        );
        links.insert(self.device_id.clone(), link.clone());
        Ok(link)
    }
}
