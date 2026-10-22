//! The one owner of this device's iroh peer connectivity.
//!
//! ```text
//!   PeerConnectivityRuntime            process lifetime, on DaemonState
//!     ├─ own address publication       the iroh endpoint's address, to
//!     │                                the plane (`report_own_address`)
//!     ├─ peer substrate reachability   what the plane reported per peer
//!     ├─ peer reachability             what this device's iroh connections
//!     │                                to each peer show: direct, relay,
//!     │                                connecting, unreachable
//!     ├─ peer sessions                 one per pinned peer the endpoint
//!     │                                reaches, while it reaches it
//!     │                                (`keep_peer_sessions`)
//!     └─ bind_endpoint ──────────────► IrohEndpoint   stack lifetime
//!                                        ├─ iroh Endpoint + Router
//!                                        │   (sync ALPN + Track Send ALPN)
//!                                        ├─ admission (pinned signing keys;
//!                                        │   Track Send has its own)
//!                                        ├─ address lookup (coordination,
//!                                        │   + LAN for authorized peers)
//!                                        ├─ link cache, one link per peer
//!                                        ├─ open connections, dialled and
//!                                        │   accepted, for revocation
//!                                        └─ endpoint id <-> device
//! ```
//!
//! Two lifetimes, one owner. What a peer's reachability is, and what this
//! device publishes about itself, outlives any one endpoint: the netmap is
//! usually applied before an endpoint exists, and what it recorded has to be
//! replayed into the endpoint's directory the moment there is one. The
//! endpoint itself lives exactly as long as the reconciliation stack that
//! drives it, because dropping that stack is how a device stops answering
//! peers; a process-lifetime handle to it would keep a "stopped" device
//! reachable.
//!
//! Nothing here decides who a peer is or what it may do. Admission and
//! identity resolution read `PeerAuthorityState`; an address, from the plane
//! or from anywhere else, only says where an already-authorized endpoint
//! answers.
//!
//! Whole-device revocation ends here too ([`PeerConnectivityRuntime::revoke_device`]):
//! admission is checked once, when a connection is accepted, so withdrawing a
//! key refuses the NEXT connection and says nothing to the ones already up.
//! This runtime is the one place that knows every connection each endpoint
//! holds -- sync links and Track Send connections alike -- so it is the one
//! place that closes them.
//!
//! What `yadorilink status`, the health count and "available now" say about a
//! peer comes from here too ([`PeerConnectivityRuntime::reachability`]), and
//! only from the iroh endpoint's own reports -- see `reachability`. The
//! legacy QUIC transport keeps its own state in
//! `daemon_state::PeerConnectivityState` until it is removed, and no longer
//! decides what a peer's reachability is.

mod address_report;
mod link_cache;
mod peer_sessions;
mod reachability;
#[cfg(any(test, feature = "test-support"))]
pub mod reachability_source_for_tests;

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::{mpsc, watch};
use yadorilink_sync_substrate::{
    Carrier, LinkEvent, LinkObserver, NetworkConfig, PeerAddress, PeerAdmission, PeerId, PeerLink,
    SubstrateNode, TrackSendConnection, TrackSendConnections,
};

use crate::coordination_client::SubstrateReachability;
use crate::daemon_state::PeerAuthorityState;
use crate::peer_registry::{PeerReachability, UnreachableCategory};
use crate::sync_adapter::address_directory::CoordinationAddressDirectory;
pub use address_report::report_own_address;
pub(crate) use peer_sessions::keep_peer_sessions;
use reachability::{LinkId, LinkReachability};

/// Comma-separated relay URLs for the reconciliation substrate.
///
/// Unset means Iroh's own relay infrastructure — free, needs no configuration,
/// and reachable from anywhere. Setting it moves to a specific relay set
/// (Yadori-operated, a managed tier, self-hosted) within the same iroh
/// abstraction, which is what makes starting on the public ones a decision
/// that can be revisited without touching anything above the substrate.
///
/// [`NO_RELAYS`] turns relaying off entirely, for a deployment that is
/// strictly local-area and does not want a device reaching third-party
/// infrastructure at all. That is a real configuration, not a way to select a
/// different convergence path: there is only one.
const SYNC_RELAYS_ENV: &str = "YADORILINK_SYNC_RELAYS";

/// The [`SYNC_RELAYS_ENV`] value that means "no relays, direct only".
///
/// Spelled out rather than expressed as an empty value, because an empty
/// setting is indistinguishable from an unset one and must keep meaning "not
/// configured" — a deployment that meant to turn relaying off and a
/// deployment that never configured it want opposite things, and silently
/// giving both the same answer would leave one of them with peers it cannot
/// reach and no indication why.
const NO_RELAYS: &str = "none";

/// The substrate's network configuration, from this daemon's environment.
pub(crate) fn sync_network_config() -> NetworkConfig {
    let configured = std::env::var(SYNC_RELAYS_ENV).unwrap_or_default();
    if configured.trim().eq_ignore_ascii_case(NO_RELAYS) {
        return NetworkConfig::direct_only().with_lan_discovery();
    }
    let (network, rejected) = NetworkConfig::from_relay_urls(configured.split(','));
    for url in rejected {
        tracing::warn!(%url, "ignoring an unparsable sync relay URL");
    }
    // Same-LAN peers keep finding each other while the coordination plane,
    // the relays or the internet are unreachable. Only for peers this device
    // already authorizes -- `bind_endpoint` supplies that filter.
    network.with_lan_discovery()
}

/// This device's iroh connectivity: what it publishes about itself, what the
/// coordination plane reported about each peer, and the only way to bind an
/// iroh endpoint.
pub struct PeerConnectivityRuntime {
    /// This device's substrate reachability, as the substrate last published
    /// it -- both halves of ONE address snapshot.
    ///
    /// A watch and not a value read once at startup: the home relay is
    /// assigned after the endpoint binds and can move afterwards, so a device
    /// that sampled this at startup would advertise "no relay" for the life of
    /// the process — and to a peer that cannot reach it directly, a device
    /// with no relay is a device that is not there.
    ///
    /// `None` until the substrate has published once. That is not the same
    /// claim as "reachable nowhere", and the endpoint report keeps the two
    /// apart: absent means "leave what you have", present-and-empty means
    /// "currently nowhere".
    ///
    /// One watch rather than two because the halves describe one address
    /// generation. Published independently they could describe two, and a peer
    /// would dial a direct address from one alongside a relay from another.
    pub local_substrate_reachability: watch::Receiver<Option<SubstrateReachability>>,
    local_substrate_reachability_tx: watch::Sender<Option<SubstrateReachability>>,
    /// Substrate reachability the plane has reported per peer. Present only
    /// for a peer whose plane supplied the field at least once -- absence here
    /// means "never told", never "told it is nowhere".
    peer_substrate_reachability: Mutex<HashMap<String, SubstrateReachability>>,
    /// The connections of every endpoint this runtime has bound and that is
    /// still alive, so a revocation reaches all of them. Weak: an endpoint
    /// lives exactly as long as the stack that holds it, and this registry
    /// must not extend that.
    endpoints: Mutex<Vec<Weak<OpenConnections>>>,
    /// Every peer's connections and dials, as the iroh endpoint reported
    /// them, and the reachability they add up to.
    reachability: Mutex<LinkReachability>,
    /// This device, for the measurement-only join timeline.
    local_device_id: String,
}

impl PeerConnectivityRuntime {
    pub(crate) fn new(local_device_id: String) -> Self {
        let (local_substrate_reachability_tx, local_substrate_reachability) = watch::channel(None);
        Self {
            local_substrate_reachability,
            local_substrate_reachability_tx,
            peer_substrate_reachability: Mutex::new(HashMap::new()),
            endpoints: Mutex::new(Vec::new()),
            reachability: Mutex::new(LinkReachability::default()),
            local_device_id,
        }
    }

    /// Measurement only: records `milestone` on every join timeline of this
    /// device that shares a group with `peer_device`.
    fn mark_peer_groups(
        &self,
        authority: &PeerAuthorityState,
        peer_device: &str,
        milestone: yadorilink_fs_platform::join_timeline::Milestone,
    ) {
        if !yadorilink_fs_platform::join_timeline::is_active() {
            return;
        }
        for group in authority.authorized_groups_for_peer(peer_device) {
            yadorilink_fs_platform::join_timeline::mark_with_peer(
                &self.local_device_id,
                &group,
                milestone,
                peer_device,
            );
        }
    }

    fn links(&self) -> std::sync::MutexGuard<'_, LinkReachability> {
        self.reachability.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// How `device_id` can be reached right now, from this device's iroh
    /// connections to it; `None` when there is no connection, no dial and no
    /// failure to report.
    pub fn reachability(&self, device_id: &str) -> Option<PeerReachability> {
        self.links().get(device_id)
    }

    /// Every peer with something to report, and its reachability. Order is
    /// unspecified.
    pub fn every_peer_reachability(&self) -> Vec<(String, PeerReachability)> {
        self.links().all()
    }

    /// How many peers are connected right now, directly or through a relay.
    pub fn connected_peer_count(&self) -> u32 {
        self.links().all().iter().filter(|(_, r)| r.is_connected()).count() as u32
    }

    /// Whether a live connection to `device_id` opened a lane speaking another protocol version.
    /// The device is reachable; it cannot sync until both ends run the same version.
    pub fn is_version_incompatible(&self, device_id: &str) -> bool {
        self.links().is_incompatible(device_id)
    }

    pub(crate) fn record_version_incompatible(&self, device_id: &str) {
        self.links().mark_incompatible(device_id);
    }

    pub(crate) fn record_dial_started(&self, device_id: &str, peer: PeerId) {
        self.links().dial_started(device_id, peer);
    }

    pub(crate) fn record_dial_failed(&self, peer: PeerId, why: UnreachableCategory) {
        self.links().dial_failed(peer, why);
    }

    pub(crate) fn record_link_up(&self, device_id: &str, carrier: Option<Carrier>) -> LinkId {
        self.links().link_up(device_id, carrier)
    }

    pub(crate) fn record_carrier(&self, device_id: &str, link: LinkId, carrier: Option<Carrier>) {
        self.links().carrier_changed(device_id, link, carrier);
    }

    pub(crate) fn record_link_closed(&self, device_id: &str, link: LinkId) {
        self.links().link_closed(device_id, link);
    }

    /// What the iroh endpoint reports about a connection it dialled or
    /// accepted, turned into `device`'s reachability.
    ///
    /// Only peers the netmap pins are recorded; admission refuses anyone
    /// else, and a dial is only ever made to a pinned key.
    fn observe_link(self: &Arc<Self>, authority: &PeerAuthorityState, event: LinkEvent<'_>) {
        match event {
            LinkEvent::Dialing(peer) => {
                if let Some(device) = authority.device_id_for_signing_key(peer.as_bytes()) {
                    self.mark_peer_groups(
                        authority,
                        &device,
                        yadorilink_fs_platform::join_timeline::Milestone::LinkDialStarted,
                    );
                    self.record_dial_started(&device, peer);
                }
            }
            LinkEvent::Dialed(peer, Err(failure)) => {
                self.record_dial_failed(peer, reachability::unreachable_because(failure));
            }
            LinkEvent::Dialed(peer, Ok(link)) => {
                let device = self
                    .links()
                    .dial_connected(peer)
                    .or_else(|| authority.device_id_for_signing_key(peer.as_bytes()));
                if let Some(device) = device {
                    self.mark_peer_groups(
                        authority,
                        &device,
                        yadorilink_fs_platform::join_timeline::Milestone::CarrierEstablished,
                    );
                    self.follow_link(device, link);
                }
            }
            LinkEvent::Accepted(link) => {
                if let Some(device) = authority.device_id_for_signing_key(link.peer().as_bytes()) {
                    self.mark_peer_groups(
                        authority,
                        &device,
                        yadorilink_fs_platform::join_timeline::Milestone::CarrierEstablished,
                    );
                    self.follow_link(device, link);
                }
            }
        }
    }

    /// Records `link` as one of `device`'s connections and follows its
    /// selected path until it closes.
    ///
    /// The follower holds no strong handle on the connection: whoever owns it
    /// decides how long it lives, and a connection they dropped must stop
    /// counting as reachable rather than be kept open by being watched.
    fn follow_link(self: &Arc<Self>, device: String, link: &PeerLink) {
        let mut changes = link.carrier_changes();
        let id = self.record_link_up(&device, link.carrier());
        let runtime = self.clone();
        tokio::spawn(async move {
            while let Some(carrier) = changes.next().await {
                runtime.record_carrier(&device, id, carrier);
            }
            runtime.record_link_closed(&device, id);
        });
    }

    /// End everything this device's iroh connectivity still offers
    /// `device_id`, once the netmap has withdrawn it.
    ///
    /// Must be called AFTER the device's signing key has left
    /// `PeerAuthorityState`, and with no lock held: withdrawing the key is
    /// what stops the device's next connection being admitted, and closing
    /// first would leave a window in which the device, seeing its connection
    /// drop, reconnects and is accepted -- exactly the state this prevents.
    /// `signing_key` is the key the device had before it was withdrawn, read
    /// by the caller while it was still there.
    ///
    /// Closes every connection each live endpoint holds to a peer it no
    /// longer admits -- the cached links this device dialled and the
    /// connections it accepted -- and `signing_key`'s Track Send
    /// connections, in either direction, once Track Send's own admission
    /// no longer admits it either (a live grant still does, exactly as it
    /// would admit a new connection). It forgets where that peer answers: the
    /// reachability the plane reported and the endpoint directory's entry.
    /// It also stops being listed as reachable at once, rather than when its
    /// closed connections are next noticed. A local-network announcement needs no forgetting, because LAN lookup
    /// asks `PeerAuthorityState` on every resolve and now answers nothing.
    ///
    /// Synchronous, and takes only short locks (this runtime's own, and the
    /// reads Track Send's admission makes): closing a connection is a local
    /// state change that iroh then tells the far side about by itself.
    pub(crate) fn revoke_device(&self, device_id: &str, signing_key: Option<[u8; 32]>) {
        self.peer_substrate_reachability
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(device_id);
        self.links().forget(device_id);
        let endpoints: Vec<Arc<OpenConnections>> = {
            let mut endpoints = self.endpoints.lock().unwrap_or_else(|p| p.into_inner());
            endpoints.retain(|endpoint| endpoint.strong_count() > 0);
            endpoints.iter().filter_map(Weak::upgrade).collect()
        };
        for endpoint in endpoints {
            endpoint.revoke(signing_key.map(PeerId::from_bytes));
        }
    }

    /// Bind this device's iroh endpoint and router, identified by its signing
    /// key, admitting exactly the peers `authority` currently pins to the
    /// sync ALPN, and exactly the peers `track_send` admits to Track Send's.
    ///
    /// The two admissions are deliberately independent: a pinned sync peer
    /// is not thereby allowed to send this device a file, and a device let
    /// in for Track Send is not thereby a sync peer. Accepted Track Send
    /// connections wait on the endpoint until their one consumer takes them
    /// ([`IrohEndpoint::take_track_send_inbound`]).
    ///
    /// The only place in the daemon an iroh endpoint is built. Returns the
    /// live endpoint and the stream of inbound links, which the caller must
    /// drain.
    ///
    /// The endpoint identity is this device's signing key, so the netmap
    /// already publishes the binding peers need to recognise it — see
    /// `SubstrateNode::spawn_as_device`.
    pub(crate) async fn bind_endpoint(
        self: &Arc<Self>,
        signing_key: [u8; 32],
        authority: &Arc<PeerAuthorityState>,
        track_send: Arc<dyn PeerAdmission>,
        nas_admin: Option<Arc<dyn yadorilink_sync_substrate::NasAdminAuthorizer>>,
        config: NetworkConfig,
    ) -> Result<(IrohEndpoint, mpsc::Receiver<PeerLink>), yadorilink_sync_substrate::SubstrateError>
    {
        // Where peers are, asked of the coordination plane rather than pushed
        // in as a candidate list -- see `address_directory`'s own module doc.
        let directory = CoordinationAddressDirectory::new(self);

        // Who may open a lane with us. A `PeerId` is a device's Ed25519
        // signing key, so this is the same pinned-key map the netmap
        // maintains, asked the other way round: a peer is admitted exactly
        // when `PeerAuthorityState` currently holds its signing key. That is
        // identity, not group authorization -- a pinned peer with no
        // authorized group (a netmap entry whose groups are still being
        // validated, or a demoted writer) is admitted here, and what it may
        // read or write is enforced per group further in.
        //
        // Read live on each new connection rather than snapshotted here.
        // The key leaves the map only when the netmap stops listing the
        // device (`teardown_peer` -> `clear_peer_netmap_metadata`) or lists
        // it without a key, and from then on its NEXT connection is refused;
        // a connection this predicate already admitted is not re-checked by
        // it.
        //
        // Weak, so this policy does not by itself keep the authority state
        // alive. It refuses once every strong `Arc<PeerAuthorityState>` is
        // gone -- `DaemonState`'s and LAN discovery's -- which is the correct
        // answer in any case.
        let peers = Arc::downgrade(authority);
        let peer_admission = yadorilink_sync_substrate::AdmitWhen::new(move |peer: &PeerId| {
            peers.upgrade().is_some_and(|authority| admits(&authority, peer))
        });

        // Which endpoints a local-network announcement may be used for, when
        // `config` asks for LAN lookup at all. Anyone on the LAN can announce
        // any key, so the announcement decides nothing: an address found
        // there is used only for a device the netmap pins AND authorizes for
        // at least one group, read live on every lookup so a revocation
        // takes effect on the next one. Everything else is never resolved,
        // and so never dialled. Weak for the same reason as admission above.
        let lan_authority = Arc::downgrade(authority);
        let lan_peers = yadorilink_sync_substrate::AdmitWhen::new(move |peer: &PeerId| {
            lan_authority
                .upgrade()
                .is_some_and(|authority| authority.is_authorized_lan_peer(peer.as_bytes()))
        });

        // What a peer's reachability is, from every connection this endpoint
        // dials or accepts -- the only source of it. Weak for the same reason
        // as admission: telling this runtime about a connection must not keep
        // the authority state alive.
        let observed_authority = Arc::downgrade(authority);
        let runtime = self.clone();
        let observer = LinkObserver::new(move |event| {
            if let Some(authority) = observed_authority.upgrade() {
                runtime.observe_link(&authority, event);
            }
        });

        let (track_send_tx, track_send_inbound) = mpsc::channel(TRACK_SEND_QUEUE);
        // Native replication is offered to exactly the devices that may sync
        // with this one: the same admission, asked again on revocation.
        let (native_replication_tx, native_replication_inbound) = mpsc::channel(TRACK_SEND_QUEUE);
        // Management of this device: its own authorizer (devices on this
        // account), never the sync or Track Send admission. See `nas_admin`.
        // Not offered at all (`None`): the ALPN is not registered, and a
        // dialler is refused at the handshake.
        let mut config = config
            .with_directory(directory.clone())
            .with_lan_peers(lan_peers)
            .with_link_observer(observer)
            .with_track_send(track_send.clone(), track_send_tx)
            .with_native_replication(peer_admission.clone(), native_replication_tx);
        let mut nas_admin_inbound = None;
        if let Some(authorizer) = nas_admin {
            let (nas_admin_tx, inbound) = mpsc::channel(TRACK_SEND_QUEUE);
            config = config.with_nas_admin(authorizer.clone(), nas_admin_tx);
            nas_admin_inbound = Some((inbound, authorizer));
        }
        let (node, mut accepted) =
            SubstrateNode::spawn_as_device(signing_key, config, peer_admission).await?;

        // Every connection this endpoint accepts is held here before anything
        // serves it, so a revocation can close it. Admission ran when the
        // connection was accepted and never runs on it again; this is the
        // only thing that can end it later.
        let open = Arc::new(OpenConnections {
            authority: Arc::downgrade(authority),
            directory: directory.clone(),
            links: Mutex::new(Vec::new()),
            track_send,
            track_send_connections: node.track_send_connections(),
            native_replication_connections: node.native_replication_connections(),
        });
        self.endpoints.lock().unwrap_or_else(|p| p.into_inner()).push(Arc::downgrade(&open));
        let (inbound_tx, inbound) = mpsc::channel(ACCEPTED_QUEUE);
        let links = Arc::new(link_cache::LinkCache::default());
        {
            let open = open.clone();
            let links = links.clone();
            let authority = Arc::downgrade(authority);
            tokio::spawn(async move {
                loop {
                    let link = tokio::select! {
                        link = accepted.recv() => match link {
                            Some(link) => link,
                            None => return,
                        },
                        () = inbound_tx.closed() => return,
                    };
                    if !open.hold(&link) {
                        tracing::debug!(
                            peer = ?link.peer(),
                            "closed an accepted sync connection whose device was revoked before it was served"
                        );
                        continue;
                    }
                    // An admitted peer's connection is as good a link as one
                    // this device dialled: whoever is waiting on a dial
                    // takes it.
                    if let Some(device) = authority.upgrade().and_then(|authority| {
                        authority.device_id_for_signing_key(link.peer().as_bytes())
                    }) {
                        links.offer_accepted(&device, &link);
                    }
                    if inbound_tx.send(link.clone()).await.is_err() {
                        link.close();
                        return;
                    }
                }
            });
        }

        Ok((
            IrohEndpoint {
                node,
                directory,
                authority: authority.clone(),
                links,
                open,
                track_send_inbound: Mutex::new(Some(track_send_inbound)),
                native_replication_inbound: Mutex::new(Some(native_replication_inbound)),
                nas_admin_inbound: Mutex::new(nas_admin_inbound),
            },
            inbound,
        ))
    }

    /// Publishes this device's substrate endpoint addresses, as iroh reports
    /// them through the address directory.
    ///
    /// Both halves come from one snapshot of the substrate's own address, so
    /// they cannot disagree, and iroh republishes on every change -- including
    /// the rebind after a restart, which is what makes a one-time publication
    /// wrong.
    pub fn publish_substrate_endpoint(
        &self,
        direct: Vec<std::net::SocketAddr>,
        relays: Vec<String>,
    ) {
        let snapshot = SubstrateReachability { direct, relays };
        // Sent only on a real change, so a republish of identical addresses
        // does not become a heartbeat.
        if self.local_substrate_reachability.borrow().as_ref() != Some(&snapshot) {
            let _ = self.local_substrate_reachability_tx.send(Some(snapshot.clone()));
        }
    }

    /// Records the substrate reachability the coordination plane reports for
    /// `device_id`, and returns whether the recorded value changed.
    ///
    /// Never calls out: waking the peer session driver is the caller's job
    /// (`DaemonState::record_peer_substrate_reachability`), done after this
    /// lock is released.
    pub(crate) fn record_peer_substrate_reachability(
        &self,
        device_id: &str,
        reachability: SubstrateReachability,
    ) -> bool {
        let mut recorded =
            self.peer_substrate_reachability.lock().unwrap_or_else(|p| p.into_inner());
        recorded.insert(device_id.to_string(), reachability.clone()) != Some(reachability)
    }

    /// The substrate reachability the coordination plane last reported for
    /// `device_id`, or `None` if it has never supplied one.
    pub(crate) fn substrate_reachability(&self, device_id: &str) -> Option<SubstrateReachability> {
        self.peer_substrate_reachability
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(device_id)
            .cloned()
    }

    /// Every peer this device has any recorded reachability for, so a consumer
    /// that did not exist when the netmap arrived can be brought up to date.
    pub(crate) fn peers_with_recorded_reachability(&self) -> Vec<String> {
        let devices: std::collections::BTreeSet<String> = self
            .peer_substrate_reachability
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .cloned()
            .collect();
        devices.into_iter().collect()
    }

    /// Projects what is recorded for `device_id` into `endpoint`'s address
    /// directory: pinned signing key -> endpoint id, plus whatever
    /// reachability the plane reported.
    ///
    /// `None` is "this peer has not published a substrate address yet", not
    /// "it is reachable nowhere": record nothing and wait for the netmap
    /// update its publish produces. Substituting some other list here would be
    /// recording an address the substrate never claimed.
    pub(crate) fn project_peer_address(&self, device_id: &str, endpoint: &IrohEndpoint) {
        let Some(peer) = endpoint.peer_id_of(device_id) else {
            return;
        };
        if let Some(r) = self.substrate_reachability(device_id) {
            endpoint.directory.record(peer, r.direct, r.relays);
        }
    }
}

/// How many accepted connections may wait to be served. Matches the
/// substrate's own inbound queue, so holding them here adds no new limit.
const ACCEPTED_QUEUE: usize = 64;

/// How many accepted Track Send connections may wait for the Track Send
/// service. Sends are sporadic and one-shot; the router's accept task for a
/// connection waits here rather than dropping it.
const TRACK_SEND_QUEUE: usize = 16;

/// Whether `authority` admits `peer` at all: the netmap pins its signing key.
///
/// The one predicate both admission and revocation ask, so a connection is
/// closed on revocation exactly when a new one from that peer would be
/// refused.
fn admits(authority: &PeerAuthorityState, peer: &PeerId) -> bool {
    authority.device_id_for_signing_key(peer.as_bytes()).is_some()
}

/// The connections one endpoint holds to peers, dialled or accepted, and
/// where it looks them up -- what a revocation has to reach.
struct OpenConnections {
    /// Weak for the same reason as the admission policy: this does not keep
    /// the authority state alive, and admits nobody once it is gone.
    authority: Weak<PeerAuthorityState>,
    directory: Arc<CoordinationAddressDirectory>,
    /// Clones of connections that are already kept open elsewhere -- by the
    /// link cache, or by the substrate for as long as an accepted connection
    /// lives -- so holding them here extends no connection's life.
    links: Mutex<Vec<PeerLink>>,
    /// Who may open a Track Send connection, asked again on revocation so a
    /// device's Track Send connections are closed exactly when a new one
    /// from it would be refused.
    track_send: Arc<dyn PeerAdmission>,
    /// The Track Send connections this endpoint dialled or accepted.
    track_send_connections: TrackSendConnections,
    /// The native replication connections this endpoint dialled or
    /// accepted, closed when the device is no longer admitted.
    native_replication_connections: yadorilink_sync_substrate::NativeReplicationConnections,
}

impl OpenConnections {
    fn admits(&self, peer: &PeerId) -> bool {
        self.authority.upgrade().is_some_and(|authority| admits(&authority, peer))
    }

    /// Hold `link` so a later revocation reaches it. Returns `false`, having
    /// closed it, when its peer is no longer admitted.
    ///
    /// Held FIRST and checked second. A revocation withdraws the key and
    /// then sweeps under this lock, so a link held after that sweep sees
    /// the withdrawn key here, and a link held before it is closed by it.
    fn hold(&self, link: &PeerLink) -> bool {
        {
            let mut links = self.links.lock().unwrap_or_else(|p| p.into_inner());
            links.retain(PeerLink::is_alive);
            links.push(link.clone());
        }
        if self.admits(&link.peer()) {
            return true;
        }
        link.close();
        false
    }

    /// Close every held connection to a peer that is no longer admitted,
    /// and forget where `peer` answers if it is one of them. `peer`'s Track
    /// Send connections, both directions, are closed too once Track Send's
    /// own admission no longer admits it.
    fn revoke(&self, peer: Option<PeerId>) {
        if let Some(peer) = peer {
            if !self.admits(&peer) {
                self.directory.forget(peer);
            }
            if !self.track_send.admit(&peer) {
                self.track_send_connections.close_to(&peer);
            }
            if !self.admits(&peer) {
                self.native_replication_connections.close_to(&peer);
            }
        }
        let mut links = self.links.lock().unwrap_or_else(|p| p.into_inner());
        links.retain(|link| {
            if !link.is_alive() {
                return false;
            }
            if self.admits(&link.peer()) {
                return true;
            }
            link.close();
            false
        });
    }
}

/// One bound iroh endpoint and router, and everything whose lifetime is that
/// endpoint's: who it admits, where it looks peers up, and the links it holds
/// open.
///
/// Constructed only by [`PeerConnectivityRuntime::bind_endpoint`].
pub struct IrohEndpoint {
    node: SubstrateNode,
    directory: Arc<CoordinationAddressDirectory>,
    authority: Arc<PeerAuthorityState>,
    /// One connection per peer, shared by every lane this device opens to it.
    ///
    /// Resolved per call rather than held open forever: a link that has gone
    /// away is redialled, and the flow-control separation between lanes only
    /// means anything if they are lanes of the *same* connection.
    links: Arc<link_cache::LinkCache>,
    /// Every connection this endpoint holds, dialled into `links` or
    /// accepted, for [`PeerConnectivityRuntime::revoke_device`] to close.
    open: Arc<OpenConnections>,
    /// Track Send connections this endpoint admitted, until the Track Send
    /// service takes the queue. Kept apart from every sync structure above:
    /// they are never cached, observed for reachability, or served as lanes.
    track_send_inbound: Mutex<Option<mpsc::Receiver<TrackSendConnection>>>,
    native_replication_inbound:
        Mutex<Option<mpsc::Receiver<yadorilink_sync_substrate::NativeReplicationConnection>>>,
    /// Authorized management connections, with the authorizer that admitted
    /// them (asked again for every stream), until `nas_admin::run` takes them.
    nas_admin_inbound: Mutex<Option<NasAdminInbound>>,
}

/// What `nas_admin::run` takes from the endpoint.
pub(crate) type NasAdminInbound = (
    mpsc::Receiver<yadorilink_sync_substrate::NasAdminConnection>,
    Arc<dyn yadorilink_sync_substrate::NasAdminAuthorizer>,
);

impl IrohEndpoint {
    /// The running node, for the reconciliation runtime layered on it. A
    /// clone shares the same endpoint and router.
    pub(crate) fn node(&self) -> SubstrateNode {
        self.node.clone()
    }

    /// This device's transport identity, which is also its signing key's
    /// public half — what a peer's netmap already pins for it.
    pub(crate) fn peer_id(&self) -> PeerId {
        self.node.peer_id()
    }

    /// The address a peer's netmap should record for this device.
    pub(crate) fn local_address(&self) -> PeerAddress {
        self.node.local_address()
    }

    /// This device's address, updated as the substrate learns more of it.
    pub(crate) fn watch_local_address(&self) -> watch::Receiver<PeerAddress> {
        self.node.watch_local_address()
    }

    /// Where this device publishes and resolves substrate endpoint addresses.
    pub(crate) fn address_directory(&self) -> &Arc<CoordinationAddressDirectory> {
        &self.directory
    }

    /// The endpoint identity of `device_id`, from the netmap.
    ///
    /// `None` when the netmap has not pinned that device's signing key. An
    /// endpoint id IS the device's signing key, so this is the whole of the
    /// identity resolution: with no pinned key there is nothing to dial, and
    /// dialling something this device cannot name is not a thing to attempt.
    pub(crate) fn peer_id_of(&self, device_id: &str) -> Option<PeerId> {
        self.authority.peer_signing_key(device_id).map(PeerId::from_bytes)
    }

    /// The device this endpoint identity belongs to, per the netmap.
    pub(crate) fn device_for_peer(&self, peer: &PeerId) -> Option<String> {
        self.authority.device_id_for_signing_key(peer.as_bytes())
    }

    /// The connection to `device_id`, dialled through `dial` if there is not
    /// a live one; `Ok(None)` when the netmap pins no key for that device.
    ///
    /// `dial` is the caller's, so a dial made for the link cache is seen by
    /// the same observers as every other dial the reconciliation runtime
    /// makes. Concurrent callers for one peer share one dial, and no lock is
    /// held across it: an authorized link the peer opens while the dial is
    /// still pending completes the call at once (see `link_cache`).
    #[cfg(test)]
    pub(crate) async fn link_to<E, Fut>(
        &self,
        device_id: &str,
        dial: impl FnOnce(PeerId) -> Fut,
    ) -> Result<Option<Arc<PeerLink>>, E>
    where
        Fut: Future<Output = Result<PeerLink, E>> + Send + 'static,
        E: Send + 'static,
    {
        self.link_to_adopting(device_id, |_| {}, dial).await
    }

    /// [`Self::link_to`], calling `adopt` on a dialled link once it is held
    /// (admitted and revocable) and before it is cached or handed out.
    pub(crate) async fn link_to_adopting<E, Fut>(
        &self,
        device_id: &str,
        adopt: impl Fn(&PeerLink) + Send + 'static,
        dial: impl FnOnce(PeerId) -> Fut,
    ) -> Result<Option<Arc<PeerLink>>, E>
    where
        Fut: Future<Output = Result<PeerLink, E>> + Send + 'static,
        E: Send + 'static,
    {
        let (authority, device) = (self.authority.clone(), device_id.to_string());
        let open = self.open.clone();
        self.links
            .link_to(
                device_id,
                move || authority.peer_signing_key(&device).map(PeerId::from_bytes),
                move |link| open.hold(link),
                adopt,
                dial,
            )
            .await
    }

    /// Resolves when a live link to `device_id` is current, however it came
    /// to be (dialled, or opened by the peer meanwhile). Never resolves for a
    /// device the netmap pins no key for.
    pub(crate) async fn wait_for_link(&self, device_id: &str) {
        match self.peer_id_of(device_id) {
            Some(peer) => {
                self.links.wait_for_link(device_id, peer).await;
            }
            None => std::future::pending::<()>().await,
        }
    }

    /// The queue of admitted Track Send connections. `None` after the first
    /// call: the queue has exactly one consumer, the Track Send service.
    pub(crate) fn take_track_send_inbound(&self) -> Option<mpsc::Receiver<TrackSendConnection>> {
        self.track_send_inbound.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// The queue of admitted native replication connections. `None` after the
    /// first call: the queue has exactly one consumer.
    pub(crate) fn take_native_replication_inbound(
        &self,
    ) -> Option<mpsc::Receiver<yadorilink_sync_substrate::NativeReplicationConnection>> {
        self.native_replication_inbound.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// The queue of authorized management connections and their
    /// authorizer. `None` after the first call: one consumer.
    pub(crate) fn take_nas_admin_inbound(&self) -> Option<NasAdminInbound> {
        self.nas_admin_inbound.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// Dial `peer` on the native replication ALPN.
    pub(crate) async fn connect_native_replication(
        &self,
        peer: PeerId,
    ) -> Result<
        yadorilink_sync_substrate::NativeReplicationConnection,
        yadorilink_sync_substrate::SubstrateError,
    > {
        use yadorilink_sync_substrate::AddressDirectory;
        let mut address = yadorilink_sync_substrate::PeerAddress::new(peer);
        if let Some((direct, relays)) = self.directory.resolve(peer) {
            address = address.with_direct(direct).with_relays(relays);
        }
        self.node.connect_native_replication(&address).await
    }

    /// Dial `peer` on NAS management's ALPN, from this device's own
    /// endpoint (so the remote sees this device's key).
    ///
    /// `hints` are added to what the netmap's directory knows: a device on
    /// this account that shares no folder with this one has no netmap entry,
    /// so its caller passes the reachability the coordination plane listed.
    pub(crate) async fn connect_nas_admin(
        &self,
        peer: PeerId,
        hints: crate::coordination_client::SubstrateReachability,
    ) -> Result<
        yadorilink_sync_substrate::NasAdminConnection,
        yadorilink_sync_substrate::NasAdminError,
    > {
        use yadorilink_sync_substrate::AddressDirectory;
        let mut address = yadorilink_sync_substrate::PeerAddress::new(peer)
            .with_direct(hints.direct)
            .with_relays(hints.relays);
        if let Some((direct, relays)) = self.directory.resolve(peer) {
            address = address.with_direct(direct).with_relays(relays);
        }
        self.node.connect_nas_admin(&address).await
    }

    /// Close the endpoint and every connection on it.
    ///
    /// A peer learns that this device has gone away from the connection
    /// closing, and from nothing else -- see `SyncStack::shutdown`.
    pub(crate) async fn shutdown(&self) {
        self.node.shutdown().await;
    }
}

#[cfg(test)]
mod iroh_reachability_tests;

#[cfg(test)]
mod link_cache_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// `none` turns relaying off; an unset or empty value means "not
    /// configured" and keeps the default.
    ///
    /// The two must not collapse into one answer: a deployment that meant to
    /// keep its devices off third-party infrastructure and a deployment that
    /// simply never configured relays want opposite things.
    #[test]
    fn only_an_explicit_none_turns_relaying_off() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other reader of this variable in
        // this test module by `ENV_LOCK`.
        unsafe { std::env::remove_var(SYNC_RELAYS_ENV) };
        assert!(sync_network_config().relays_configured(), "unset must keep the default");

        unsafe { std::env::set_var(SYNC_RELAYS_ENV, "   ") };
        assert!(sync_network_config().relays_configured(), "empty must keep the default");

        unsafe { std::env::set_var(SYNC_RELAYS_ENV, "None") };
        assert!(!sync_network_config().relays_configured(), "`none` must turn relaying off");

        unsafe { std::env::remove_var(SYNC_RELAYS_ENV) };
    }

    /// Same-LAN lookup is on in every production configuration, including a
    /// strictly local one with relaying off -- that deployment needs it most.
    #[test]
    fn every_production_configuration_looks_peers_up_on_the_lan() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized by `ENV_LOCK`, as above.
        unsafe { std::env::remove_var(SYNC_RELAYS_ENV) };
        assert!(sync_network_config().lan_discovery(), "default relays");

        unsafe { std::env::set_var(SYNC_RELAYS_ENV, "none") };
        assert!(sync_network_config().lan_discovery(), "relaying off");

        unsafe { std::env::set_var(SYNC_RELAYS_ENV, "https://relay.example.test") };
        assert!(sync_network_config().lan_discovery(), "custom relays");

        unsafe { std::env::remove_var(SYNC_RELAYS_ENV) };
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
