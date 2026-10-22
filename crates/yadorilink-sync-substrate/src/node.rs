//! The networking substrate node: `YadoriSyncProtocol` registered as its own
//! ALPN on an iroh endpoint.
//!
//! Why iroh directly, and not `p2panda-net` / `p2panda-sync`:
//!
//! * `p2panda_sync::traits::Protocol::run` runs over a *single* sink/stream
//!   pair. Yadori requires three independent flow-control domains, which a
//!   single lane cannot express.
//! * `p2panda-net` 0.7 does not expose a way to host a custom
//!   `p2panda_sync::Manager` anyway. Its generic `sync::actors::SyncManager<M>`
//!   is private; the only public entry is `LogSync`, hardcoded to
//!   `TopicSyncManager` and the append-only-log store traits.
//! * What remained of `p2panda-net`'s value (address book, discovery, gossip)
//!   is reachable only through its mandatory `address_book` feature, which
//!   pulls `sqlx` and therefore `libsqlite3-sys 0.30`. That collides on the
//!   `links = "sqlite3"` native library with the `rusqlite` stack the replica
//!   store is built on, and no version selection resolves it.
//!
//! So the substrate is iroh: QUIC, NAT traversal, relay, address lookup, and
//! `Router`-dispatched ALPN handlers.

use std::collections::HashMap;
use std::sync::Arc;

use iroh::protocol::Router;
use tokio::sync::mpsc;

use crate::address::PeerAddress;
use crate::error::SubstrateError;
use crate::link::PeerLink;
use crate::peer::PeerId;

/// ALPN for `YadoriSyncProtocol`.
pub const YADORI_SYNC_ALPN: &[u8] = b"yadorilink/sync/v1";

/// Depth of the queue of inbound connections awaiting protocol dispatch.
const INBOUND_QUEUE: usize = 64;

/// How the substrate reaches the wider network.
///
/// Deliberately not iroh's `N0` preset. That preset publishes this node's
/// address to n0's pkarr/DNS service and resolves peers from it, which would
/// make peer reachability — and so, indirectly, convergence — depend on
/// third-party infrastructure Yadori does not operate, while leaking the
/// address of every node to it.
///
/// The separation instead is:
///
/// * peer identity and membership: the Yadori coordination plane
/// * `EndpointId`, relay URLs and direct addresses: the coordination plane
/// * transport, NAT traversal, relay fallback: iroh
/// * relays: explicitly configured, Yadori-operated or Yadori-selected
///
/// So no third-party address lookup service is configured. Every dial is made
/// against address information the coordination plane supplied, or -- when
/// asked for with [`NetworkConfig::with_lan_discovery`] -- what an
/// already-authorized peer announced on the local network (see `lan`).
/// An [`iroh::address_lookup::AddressLookup`] held behind an `Arc`.
///
/// Only a delegating wrapper, and only because iroh's own blanket
/// `impl<T: AddressLookup> AddressLookup for Arc<T>` is for a sized `T`, so
/// `Arc<dyn AddressLookup>` does not satisfy the builder's bound. Nothing is
/// reimplemented here: the lookup this forwards to is upstream's.
#[cfg(feature = "test-support")]
#[derive(Clone, Debug)]
struct SharedAddressLookup(Arc<dyn iroh::address_lookup::AddressLookup>);

#[cfg(feature = "test-support")]
impl iroh::address_lookup::AddressLookup for SharedAddressLookup {
    fn publish(&self, data: &iroh::address_lookup::EndpointData) {
        self.0.publish(data);
    }

    fn resolve(
        &self,
        endpoint_id: iroh::EndpointId,
    ) -> Option<
        n0_future::boxed::BoxStream<
            Result<iroh::address_lookup::Item, iroh::address_lookup::Error>,
        >,
    > {
        self.0.resolve(endpoint_id)
    }
}

#[derive(Clone, Debug, Default)]
pub struct NetworkConfig {
    relays: Relays,
    /// Where to publish this endpoint's addresses and look up other
    /// endpoints'. `None` leaves the node with no address lookup at all, which
    /// is only viable when every peer is already reachable by a path iroh
    /// holds -- see `crate::directory`.
    directory: Option<Arc<dyn crate::directory::AddressDirectory>>,
    /// Whether this node may use IP transports at all.
    ///
    /// Read only under `test-support`; a production build has no way to set it
    /// false, which is the point.
    ///
    /// Always true in production: removing them would leave a node that can
    /// only ever be relayed, which is a worse network, not a safer one. A test
    /// that has to prove something *about* the relay path sets it false, and
    /// then the relay is not a fallback but the only carrier there is — see
    /// [`NetworkConfig::relay_only_for_tests`].
    #[cfg_attr(not(feature = "test-support"), allow(dead_code))]
    ip_transports: bool,
    /// Whether to accept any relay server certificate.
    ///
    /// Only an in-process test relay, which necessarily serves a self-signed
    /// certificate. Never settable from a production configuration path: the
    /// constructors that turn it on are compiled out without `test-support`.
    #[cfg_attr(not(feature = "test-support"), allow(dead_code))]
    trust_any_relay_certificate: bool,
    /// How a deterministic simulation reconfigures this node's endpoint
    /// before it binds.
    ///
    /// `None` in production, and unsettable there: the constructor that fills
    /// it is compiled out without `test-support`, exactly as `ip_transports`
    /// above is. A simulation uses it to register a datagram carrier that is
    /// not the operating system's, so that iroh's QUIC, TLS and stream
    /// multiplexing all run for real over datagrams the simulation delivers.
    /// Nothing above this field changes: the substrate node, its lanes and
    /// every session on top are the production types.
    ///
    /// A closure rather than the transport itself, because registering one
    /// is two steps that must not come apart -- the carrier, and an address
    /// lookup that can resolve the addresses that carrier uses. iroh models
    /// the pair as a `Preset`, whose `apply` consumes `self`, so it is held
    /// here as the application rather than the value.
    /// The datagram carrier this node's endpoint runs on, when it is not the
    /// operating system's.
    ///
    /// `None` in production, and unsettable there: the constructor that fills
    /// it is compiled out without `test-support`, exactly as `ip_transports`
    /// above is.
    #[cfg(feature = "test-support")]
    custom_transport: Option<Arc<dyn iroh::endpoint::transports::CustomTransport>>,
    /// How this endpoint finds the addresses `custom_transport` can reach.
    ///
    /// Separate from the carrier, and necessarily so. A custom carrier is
    /// reachable at a [`iroh_base::CustomAddr`], and this crate's own
    /// `PeerAddress` -- what `AddressDirectory` publishes and resolves --
    /// carries socket addresses and relay URLs with no slot for one. Rather
    /// than widen that production type to serve a test, a simulation
    /// registers iroh's own lookup for its own address kind alongside the
    /// directory, and the directory stays exactly what it is.
    ///
    /// `Builder::address_lookup` appends, so this does not displace the
    /// directory lookup; both answer, and only one of them knows anything
    /// about custom addresses.
    #[cfg(feature = "test-support")]
    address_lookup_override: Option<SharedAddressLookup>,
    /// Whether to look peers up on the local network as well as in the
    /// directory. Off unless asked for: a test node has no business
    /// advertising itself on the host's network.
    lan_discovery: bool,
    /// Which endpoints a local-network answer may be used for. See `lan`:
    /// an announcement anyone on the LAN can make is no reason to talk to
    /// the endpoint it names. Absent means none -- LAN lookup fails closed.
    lan_peers: Option<Arc<dyn crate::PeerAdmission>>,
    /// Told about every connection the node dials or accepts. See `observe`.
    link_observer: Option<crate::observe::LinkObserver>,
    /// What stands in for mDNS, for a test that has to exercise the LAN path
    /// on a host that may not deliver multicast.
    #[cfg(feature = "test-support")]
    lan_source_for_tests: Option<SharedAddressLookup>,
    /// Track Send's ALPN, when this node answers it at all. See
    /// `track_send`.
    track_send: Option<crate::track_send::TrackSendAccept>,
    /// The native-replication protocol's ALPN, when this node answers it at all.
    /// Fail-closed/default-off: absent unless explicitly configured via
    /// [`NetworkConfig::with_native_replication`], exactly as `track_send` is.
    /// See `native_replication_transport`.
    native_replication: Option<crate::native_replication_transport::NativeReplicationAccept>,
    /// NAS management's ALPN, when this node answers it at all. Absent
    /// unless configured with [`NetworkConfig::with_nas_admin`]; a node
    /// without it refuses the handshake, which is what tells a dialler the
    /// device needs a newer version. See `nas_admin`.
    nas_admin: Option<crate::nas_admin::NasAdminAccept>,
}

/// Where this node falls back to when a direct path cannot be established.
#[derive(Clone, Debug, Default)]
enum Relays {
    /// None. Peers must be reachable directly — tests, and strictly
    /// local-area deployments.
    #[default]
    None,
    /// Iroh's own relay infrastructure.
    ///
    /// This is `RelayMode::Default`, which is *not* the `N0` preset. The
    /// preset would additionally publish this node's address to n0's
    /// pkarr/DNS service and resolve peers from it; that is the part Yadori
    /// must not have, because peer reachability would then depend on
    /// third-party infrastructure and every node's address would leak to it.
    /// Relaying packets is a different thing from discovering who to relay
    /// to, and only the first is delegated here — membership, identity and
    /// addresses stay with the Yadori coordination plane.
    ///
    /// A relay carries packets. It authenticates nothing, admits nothing, and
    /// is not on the path of any trust decision:
    ///
    /// ```text
    ///   relay                  packet reachability
    ///   iroh QUIC identity     transport peer authentication
    ///   proof-carrying Change  history admission authority
    /// ```
    IrohDefault,
    /// A specific relay set — Yadori-operated, a managed tier, or
    /// self-hosted. The same iroh abstraction either way, which is what makes
    /// starting on the public ones a decision that can be revisited without
    /// changing anything above this line.
    Custom(Vec<iroh::RelayUrl>),
}

impl NetworkConfig {
    /// Publishes and resolves endpoint addresses through `directory`.
    pub fn with_directory(
        mut self,
        directory: Arc<dyn crate::directory::AddressDirectory>,
    ) -> Self {
        self.directory = Some(directory);
        self
    }

    pub(crate) fn directory(&self) -> Option<Arc<dyn crate::directory::AddressDirectory>> {
        self.directory.clone()
    }

    /// Also look peers up on the local network (mDNS), so peers on the same
    /// LAN keep finding each other while the directory cannot answer.
    ///
    /// Only for endpoints [`with_lan_peers`](Self::with_lan_peers) accepts;
    /// without that, nothing found on the LAN is ever used.
    pub fn with_lan_discovery(mut self) -> Self {
        self.lan_discovery = true;
        self
    }

    /// Whether this configuration looks peers up on the local network.
    pub fn lan_discovery(&self) -> bool {
        self.lan_discovery
    }

    /// Which endpoints a local-network lookup may answer for. Asked on every
    /// lookup, so it should read live state.
    pub fn with_lan_peers(mut self, authorized: Arc<dyn crate::PeerAdmission>) -> Self {
        self.lan_peers = Some(authorized);
        self
    }

    /// Tells `observer` about every connection the node dials or accepts.
    pub fn with_link_observer(mut self, observer: crate::observe::LinkObserver) -> Self {
        self.link_observer = Some(observer);
        self
    }

    /// Also answer Track Send's ALPN on this node's router.
    ///
    /// `admission` decides who may open a Track Send connection and is the
    /// only policy asked for one -- the sync admission never is. Admitted
    /// connections are delivered to `inbound`, which the caller drains.
    pub fn with_track_send(
        mut self,
        admission: Arc<dyn crate::PeerAdmission>,
        inbound: mpsc::Sender<crate::TrackSendConnection>,
    ) -> Self {
        self.track_send = Some(crate::track_send::TrackSendAccept { admission, inbound });
        self
    }

    /// Also answer the native-replication protocol's ALPN on this node's router.
    ///
    /// Fail-closed/default-off: a `NetworkConfig` that never calls this
    /// method never dials, never accepts, and never spawns anything for
    /// the native-replication protocol -- `SubstrateNode::spawn`'s behavior for
    /// every OTHER protocol (the sync ALPN, Track Send) is byte-for-byte
    /// identical whether or not this method was ever called. `admission`
    /// decides who may open a native-replication connection and is the only
    /// policy asked for one -- the sync admission is never consulted for
    /// it, though callers are expected to configure the SAME policy in
    /// this generation (same peers, same revocation). Admitted connections
    /// are delivered to `inbound`, which the caller drains.
    pub fn with_native_replication(
        mut self,
        admission: Arc<dyn crate::PeerAdmission>,
        inbound: mpsc::Sender<crate::NativeReplicationConnection>,
    ) -> Self {
        self.native_replication =
            Some(crate::native_replication_transport::NativeReplicationAccept {
                admission,
                inbound,
            });
        self
    }

    /// Also answer NAS management's ALPN on this node's router.
    ///
    /// `authorizer` decides who may manage this device and is the only
    /// policy asked for it -- no other protocol's admission is consulted.
    /// Authorized connections are delivered to `inbound`, which the caller
    /// serves with [`crate::nas_admin::NasAdminService`].
    pub fn with_nas_admin(
        mut self,
        authorizer: Arc<dyn crate::NasAdminAuthorizer>,
        inbound: mpsc::Sender<crate::NasAdminConnection>,
    ) -> Self {
        self.nas_admin = Some(crate::nas_admin::NasAdminAccept { authorizer, inbound });
        self
    }

    /// Turns LAN lookup on with `source` standing in for mDNS. The
    /// authorization filter in front of it is the production one.
    #[cfg(feature = "test-support")]
    pub fn with_lan_source_for_tests(
        mut self,
        source: Arc<dyn iroh::address_lookup::AddressLookup>,
    ) -> Self {
        self.lan_discovery = true;
        self.lan_source_for_tests = Some(SharedAddressLookup(source));
        self
    }

    /// No relays. Peers must be reachable directly. Used by tests and by
    /// strictly local-area deployments.
    pub fn direct_only() -> Self {
        Self { relays: Relays::None, ..Self::base() }
    }

    fn base() -> Self {
        Self {
            relays: Relays::None,
            ip_transports: true,
            trust_any_relay_certificate: false,
            directory: None,
            #[cfg(feature = "test-support")]
            custom_transport: None,
            #[cfg(feature = "test-support")]
            address_lookup_override: None,
            lan_discovery: false,
            lan_peers: None,
            link_observer: None,
            #[cfg(feature = "test-support")]
            lan_source_for_tests: None,
            track_send: None,
            native_replication: None,
            nas_admin: None,
        }
    }

    /// Direct where possible, falling back to `relays` — which are expected to
    /// be an in-process test relay, so its self-signed certificate is
    /// accepted.
    ///
    /// This is the "relay is available" half of a relay comparison: a node
    /// configured this way still prefers a direct path, exactly as production
    /// does.
    #[cfg(feature = "test-support")]
    pub fn direct_or_relay_for_tests(relays: impl IntoIterator<Item = iroh::RelayUrl>) -> Self {
        Self {
            relays: Relays::Custom(relays.into_iter().collect()),
            trust_any_relay_certificate: true,
            ..Self::base()
        }
    }

    /// `relays` and nothing else: every IP transport is removed, so this node
    /// has no direct path to offer or take.
    ///
    /// This is what makes a relay test state something. Withholding a peer's
    /// direct addresses only controls the *first* path attempted — iroh will
    /// still hole-punch its way to a direct one, and a test that measured the
    /// relay carrier would quietly end up measuring a direct one partway
    /// through. Removing the transport entirely leaves the relay as the only
    /// carrier for the connection's whole life.
    #[cfg(feature = "test-support")]
    pub fn relay_only_for_tests(relays: impl IntoIterator<Item = iroh::RelayUrl>) -> Self {
        Self {
            relays: Relays::Custom(relays.into_iter().collect()),
            ip_transports: false,
            trust_any_relay_certificate: true,
            ..Self::base()
        }
    }

    /// Every datagram this node sends and receives goes through `transport`,
    /// and no IP transport is registered at all.
    ///
    /// Clearing the IP transports is not tidiness, it is the whole point, and
    /// it is the same reasoning [`NetworkConfig::relay_only_for_tests`] gives
    /// for doing it there: leaving them registered would let iroh hole-punch
    /// its way onto a real socket partway through a run, and a simulation
    /// that was exercising simulated datagrams would quietly start exercising
    /// the host's network instead -- passing either way, and proving nothing
    /// in the second case.
    #[cfg(feature = "test-support")]
    pub fn over_custom_transport(
        transport: Arc<dyn iroh::endpoint::transports::CustomTransport>,
    ) -> Self {
        Self {
            relays: Relays::None,
            ip_transports: false,
            custom_transport: Some(transport),
            ..Self::base()
        }
    }

    /// Registers `lookup` alongside whatever address lookup the directory
    /// already provides.
    ///
    /// A simulation needs this because its endpoints are reachable at an
    /// address kind the directory does not carry; see
    /// `address_lookup_override`'s own comment. Kept as a separate step from
    /// [`over_custom_transport`] rather than folded into it, so that a test
    /// can build the configuration *without* it and watch the dial fail --
    /// which is the only way to know the carrier is what the traffic rode,
    /// rather than something else that happened to work.
    ///
    /// [`over_custom_transport`]: Self::over_custom_transport
    #[cfg(feature = "test-support")]
    pub fn with_address_lookup_override(
        mut self,
        lookup: Arc<dyn iroh::address_lookup::AddressLookup>,
    ) -> Self {
        self.address_lookup_override = Some(SharedAddressLookup(lookup));
        self
    }

    /// Direct where possible, Iroh's relay infrastructure where not.
    ///
    /// The production default. See [`Relays::IrohDefault`] for why this is
    /// not the `N0` preset and why relaying is separable from discovery.
    pub fn iroh_default_relays() -> Self {
        Self { relays: Relays::IrohDefault, ..Self::base() }
    }

    /// Fall back to the given relays when a direct path cannot be established.
    pub fn with_relays(relays: impl IntoIterator<Item = iroh::RelayUrl>) -> Self {
        Self { relays: Relays::Custom(relays.into_iter().collect()), ..Self::base() }
    }

    /// Build from textual relay URLs, the shape configuration supplies.
    ///
    /// Exists so no crate above this one has to name an iroh type — the
    /// substrate is the boundary, and a `RelayUrl` in a daemon signature
    /// would put transport detail on the wrong side of it.
    ///
    /// Unparsable entries are returned rather than dropped. Silently ignoring
    /// a mistyped relay would leave a deployment that believes it has a
    /// fallback path and does not, which surfaces only as unreachable peers
    /// much later.
    pub fn from_relay_urls<'a>(urls: impl IntoIterator<Item = &'a str>) -> (Self, Vec<String>) {
        let mut relays = Vec::new();
        let mut rejected = Vec::new();
        for url in urls {
            let url = url.trim();
            if url.is_empty() {
                continue;
            }
            match url.parse() {
                Ok(parsed) => relays.push(parsed),
                Err(_) => rejected.push(url.to_string()),
            }
        }
        // Naming no relays here means "I did not configure any", not "I want
        // none": the production default is Iroh's infrastructure, and an
        // empty configuration should not silently turn that off.
        let config = if relays.is_empty() {
            Self::iroh_default_relays()
        } else {
            Self { relays: Relays::Custom(relays), ..Self::base() }
        };
        (config, rejected)
    }

    /// Whether this configuration will use any relay at all.
    ///
    /// For a caller that has to tell "no relays, deliberately" apart from
    /// "relays, whichever ones" without naming an iroh type.
    pub fn relays_configured(&self) -> bool {
        !matches!(self.relay_mode(), iroh::RelayMode::Disabled)
    }

    fn relay_mode(&self) -> iroh::RelayMode {
        match &self.relays {
            Relays::None => iroh::RelayMode::Disabled,
            Relays::IrohDefault => iroh::RelayMode::Default,
            Relays::Custom(relays) if relays.is_empty() => iroh::RelayMode::Disabled,
            Relays::Custom(relays) => iroh::RelayMode::custom(relays.iter().cloned()),
        }
    }
}

/// Whether `candidate` is a usable relay URL.
///
/// Exists so a caller above this crate can tell a relay URL from a direct
/// address without naming an iroh type — the coordination plane advertises
/// both in one list, and classifying them is the caller's job while parsing
/// them is this crate's.
pub fn is_relay_url(candidate: &str) -> bool {
    candidate.parse::<iroh::RelayUrl>().is_ok()
}

/// Registers the local-network lookup, behind the authorization filter.
fn with_lan_lookup(
    builder: iroh::endpoint::Builder,
    config: &NetworkConfig,
    local: iroh::EndpointId,
) -> iroh::endpoint::Builder {
    let authorized = config.lan_peers.clone().unwrap_or_else(|| Arc::new(crate::AdmitNone));
    #[cfg(feature = "test-support")]
    if let Some(source) = config.lan_source_for_tests.clone() {
        return builder.address_lookup(crate::lan::LanLookup::new(source, authorized));
    }
    match crate::lan::mdns(local) {
        Some(mdns) => builder.address_lookup(crate::lan::LanLookup::new(mdns, authorized)),
        None => builder,
    }
}

/// A running networking substrate.
#[derive(Debug, Clone)]
pub struct SubstrateNode {
    router: Router,
    /// This node's own address, republished whenever iroh changes it.
    ///
    /// A node's address is not known at bind time: direct addresses arrive
    /// from local interfaces and STUN-like probing, and the home relay is
    /// assigned after registering with one. Anything that publishes this
    /// device's reachability has to react to that rather than sample it once,
    /// and polling for it would be a timer wearing an event's clothes.
    address: tokio::sync::watch::Receiver<PeerAddress>,
    /// Told about every connection this node dials; the accept side holds
    /// its own clone.
    observer: Option<crate::observe::LinkObserver>,
    /// Every Track Send connection this node dialled or accepted; the
    /// Track Send handler holds its own clone.
    track_send_open: crate::TrackSendConnections,
    /// Every native-replication connection this node dialled or accepted; the
    /// native-replication handler holds its own clone. Independent of
    /// `track_send_open` and of the sync protocol's own connection
    /// lifecycle -- see `native_replication_transport`'s module doc.
    native_replication_open: crate::NativeReplicationConnections,
    /// See `dial_settle`.
    dial_settle: Arc<crate::dial_settle::DialSettle>,
}

impl SubstrateNode {
    /// Start a substrate node identified by this device's Ed25519 signing
    /// key, and register the Yadori sync ALPN.
    ///
    /// The endpoint identity is deliberately the device's own signing key,
    /// matching what `yadorilink-transport`'s QUIC identity already does and
    /// for the same reason: a TLS handshake is authenticated by *signing* a
    /// transcript, and of the keys a device already holds exactly one is
    /// signature-capable, mandatory, and already distributed to peers through
    /// the netmap. Using it is not a shortcut — it is the only option that
    /// does not invent a third identity, and it means the netmap already
    /// publishes the endpoint-to-device binding with no protocol change.
    ///
    /// Sharing the key does not weaken the separation this crate insists on.
    /// TLS 1.3 domain-separates its own signatures by construction, so a
    /// signature minted for a connection cannot be replayed as authorship;
    /// and admission never consults the carrier at all, because the
    /// verification primitive takes no parameter naming one.
    pub async fn spawn_as_device(
        device_signing_key: [u8; 32],
        config: NetworkConfig,
        admission: Arc<dyn crate::PeerAdmission>,
    ) -> Result<(Self, mpsc::Receiver<PeerLink>), SubstrateError> {
        Self::spawn(iroh::SecretKey::from_bytes(&device_signing_key), config, admission).await
    }

    /// Start a substrate node and register the Yadori sync ALPN.
    ///
    /// Returns the node and the stream of inbound peer links. The caller is
    /// responsible for draining the receiver; connections queue behind it.
    /// `admission` decides which authenticated remotes get a link. It has
    /// no default: see `admission`'s module doc for why the fail-closed
    /// guarantee depends on that being unforgettable rather than opt-in.
    pub async fn spawn(
        secret_key: iroh::SecretKey,
        config: NetworkConfig,
        admission: Arc<dyn crate::PeerAdmission>,
    ) -> Result<(Self, mpsc::Receiver<PeerLink>), SubstrateError> {
        // `Minimal` sets the mandatory crypto provider and nothing else: no
        // third-party address lookup service is registered, by design.
        #[cfg_attr(not(feature = "test-support"), allow(unused_mut))]
        let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret_key.clone())
            .relay_mode(config.relay_mode());
        // Where peers are, asked of the coordination plane rather than pushed
        // in from it. See `directory`'s own module doc for why addresses are
        // no longer an input to this node.
        if let Some(directory) = config.directory() {
            builder = builder.address_lookup(crate::directory::DirectoryLookup::new(
                directory,
                crate::peer::PeerId::from_bytes(*secret_key.public().as_bytes()),
            ));
        }
        if config.lan_discovery {
            builder = with_lan_lookup(builder, &config, secret_key.public());
        }
        #[cfg(feature = "test-support")]
        {
            if config.trust_any_relay_certificate {
                builder =
                    builder.ca_tls_config(iroh_relay::tls::CaTlsConfig::insecure_skip_verify());
            }
            if !config.ip_transports {
                builder = builder.clear_ip_transports();
            }
            if let Some(transport) = config.custom_transport.clone() {
                builder = builder.add_custom_transport(transport);
            }
            if let Some(lookup) = config.address_lookup_override.clone() {
                builder = builder.address_lookup(lookup);
            }
        }
        let endpoint =
            builder.bind().await.map_err(|err| SubstrateError::Startup(err.to_string()))?;

        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);

        let mut router = Router::builder(endpoint).accept(
            YADORI_SYNC_ALPN,
            YadoriProtocolHandler {
                inbound: Arc::new(inbound_tx),
                admission,
                observer: config.link_observer.clone(),
                connections: Arc::default(),
            },
        );
        let track_send_open = crate::TrackSendConnections::default();
        if let Some(accept) = config.track_send.clone() {
            router = router.accept(
                crate::YADORI_SEND_ALPN,
                crate::track_send::TrackSendHandler { accept, open: track_send_open.clone() },
            );
        }
        let native_replication_open = crate::NativeReplicationConnections::default();
        if let Some(accept) = config.native_replication.clone() {
            router = router.accept(
                crate::YADORI_NATIVE_REPLICATION_ALPN,
                crate::native_replication_transport::NativeReplicationHandler {
                    accept,
                    open: native_replication_open.clone(),
                },
            );
        }
        if let Some(accept) = config.nas_admin.clone() {
            router = router
                .accept(crate::YADORI_NAS_ADMIN_ALPN, crate::nas_admin::NasAdminHandler { accept });
        }
        let router = router.spawn();

        let address = spawn_address_watch(router_endpoint_of(&router));

        Ok((
            Self {
                router,
                address,
                observer: config.link_observer,
                track_send_open,
                native_replication_open,
                dial_settle: Default::default(),
            },
            inbound_rx,
        ))
    }

    /// This node's transport identity.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_bytes(*self.router.endpoint().id().as_bytes())
    }

    /// The address other nodes need in order to dial this one.
    ///
    /// This is what the coordination plane publishes on this node's behalf.
    pub fn local_address(&self) -> PeerAddress {
        peer_address_of(self.router.endpoint())
    }

    /// This node's address, updated as iroh learns more of it.
    ///
    /// The first value may name no relay at all: registration with the home
    /// relay completes after the endpoint binds. A publisher must therefore
    /// react to changes rather than read once at startup, or a device would
    /// advertise "no relay" for the life of the process and be unreachable to
    /// every peer that cannot reach it directly.
    pub fn watch_local_address(&self) -> tokio::sync::watch::Receiver<PeerAddress> {
        self.address.clone()
    }

    /// Dial a peer on the Yadori sync ALPN, using address information the
    /// coordination plane supplied.
    pub async fn connect(&self, peer: PeerId) -> Result<PeerLink, SubstrateError> {
        let endpoint_id = iroh::EndpointId::from_bytes(peer.as_bytes())
            .map_err(|err| SubstrateError::Connect(err.to_string()))?;

        let dial = crate::observe::DialInFlight::start(self.observer.as_ref(), peer);
        let connection = match self.router.endpoint().connect(endpoint_id, YADORI_SYNC_ALPN).await {
            Ok(connection) => connection,
            Err(err) => {
                dial.finish(Err(dial_failure(&err)));
                return Err(SubstrateError::Connect(err.to_string()));
            }
        };

        let link =
            PeerLink::new(PeerId::from_bytes(*connection.remote_id().as_bytes()), connection);
        dial.finish(Ok(&link));
        self.dial_settle.sync_dial_completed(peer);
        Ok(link)
    }

    /// Dial `address` on Track Send's ALPN.
    ///
    /// Not reported to the link observer: a Track Send connection is not a
    /// sync link and says nothing about the peer's sync reachability.
    pub async fn connect_track_send(
        &self,
        address: &PeerAddress,
    ) -> Result<crate::TrackSendConnection, SubstrateError> {
        crate::track_send::connect(self.router.endpoint(), &self.track_send_open, address).await
    }

    /// Every Track Send connection this node holds, for closing the ones a
    /// withdrawn device already has open.
    pub fn track_send_connections(&self) -> crate::TrackSendConnections {
        self.track_send_open.clone()
    }

    /// Dial `address` on the native-replication protocol's ALPN.
    ///
    /// Not reported to the link observer: a native-replication connection is
    /// not a sync link and says nothing about the peer's sync
    /// reachability. A failure here must never be treated as a sync
    /// failure by the caller.
    pub async fn connect_native_replication(
        &self,
        address: &PeerAddress,
    ) -> Result<crate::NativeReplicationConnection, SubstrateError> {
        self.dial_settle.before_native_dial(address.peer()).await;
        crate::native_replication_transport::connect(
            self.router.endpoint(),
            &self.native_replication_open,
            address,
        )
        .await
    }

    /// Every native-replication connection this node holds, for closing the
    /// ones a withdrawn device already has open.
    pub fn native_replication_connections(&self) -> crate::NativeReplicationConnections {
        self.native_replication_open.clone()
    }

    /// Dial `address` on NAS management's ALPN.
    ///
    /// Not reported to the link observer: a management connection says
    /// nothing about the peer's sync reachability.
    pub async fn connect_nas_admin(
        &self,
        address: &PeerAddress,
    ) -> Result<crate::NasAdminConnection, crate::NasAdminError> {
        crate::nas_admin::connect(self.router.endpoint(), address).await
    }

    /// Shut the substrate down, closing the endpoint and all connections.
    ///
    /// Yadori owns this lifecycle explicitly rather than letting the router be
    /// dropped implicitly, because restart semantics are part of the protocol
    /// contract: after a restart, reconciliation resumes from the durable
    /// verified sets and from nothing else.
    pub async fn shutdown(&self) {
        let _ = self.router.shutdown().await;
    }
}

/// What a failed dial says about the peer, in the terms a user is shown.
fn dial_failure(err: &iroh::endpoint::ConnectError) -> crate::observe::DialFailure {
    use crate::observe::DialFailure;
    use iroh::endpoint::{ConnectError, ConnectWithOptsError, ConnectingError, ConnectionError};
    match err {
        ConnectError::Connect { source: ConnectWithOptsError::NoAddress { .. }, .. } => {
            DialFailure::NoAddress
        }
        ConnectError::Connecting { source: ConnectingError::HandshakeFailure { .. }, .. } => {
            DialFailure::Refused
        }
        ConnectError::Connection {
            source: ConnectionError::ApplicationClosed(_) | ConnectionError::ConnectionClosed(_),
            ..
        } => DialFailure::Refused,
        _ => DialFailure::NoResponse,
    }
}

/// The endpoint a router was built on.
fn router_endpoint_of(router: &Router) -> iroh::Endpoint {
    router.endpoint().clone()
}

/// Turns iroh's own address watcher into a plain tokio watch of
/// [`PeerAddress`], so nothing above this crate has to name an iroh type or
/// drive an iroh-specific watcher.
fn spawn_address_watch(endpoint: iroh::Endpoint) -> tokio::sync::watch::Receiver<PeerAddress> {
    let (tx, rx) = tokio::sync::watch::channel(peer_address_of(&endpoint));
    tokio::spawn(async move {
        use iroh::Watcher as _;
        let mut watcher = endpoint.watch_addr();
        loop {
            // Ends when the endpoint stops, which is when there is nothing
            // left to publish an address for.
            if watcher.updated().await.is_err() {
                return;
            }
            if tx.send(peer_address_of(&endpoint)).is_err() {
                return;
            }
        }
    });
    rx
}

/// Splits an iroh address into the direct and relay halves a peer records.
fn peer_address_of(endpoint: &iroh::Endpoint) -> PeerAddress {
    let addr = endpoint.addr();
    let mut direct = Vec::new();
    let mut relays = Vec::new();
    for transport in &addr.addrs {
        match transport {
            iroh::TransportAddr::Ip(socket) => direct.push(*socket),
            iroh::TransportAddr::Relay(url) => relays.push(url.to_string()),
            _ => {}
        }
    }
    PeerAddress::new(PeerId::from_bytes(*endpoint.id().as_bytes()))
        .with_direct(direct)
        .with_relays(relays)
}

/// Close code for a remote that authenticated but is not one of this
/// device's peers. Distinct from a shutdown close so a dialer can tell
/// "not authorized" from "gone away" and back off accordingly.
const REFUSED_UNAUTHORIZED: u32 = 1;

/// Close code for a connection beyond the per-peer cap.
const REFUSED_TOO_MANY_CONNECTIONS: u32 = 2;

/// Most inbound connections one authenticated peer may hold open at once. A
/// peer normally holds one; a few more cover a redial that overlaps the
/// connection it replaces and both sides dialling at once. Without a cap a
/// peer could multiply its per-connection stream and lane budgets by opening
/// connections.
const MAX_INBOUND_CONNECTIONS_PER_PEER: usize = 4;

/// How many inbound connections each peer currently holds open.
#[derive(Debug, Default)]
struct InboundConnectionCounts {
    open: std::sync::Mutex<HashMap<PeerId, usize>>,
}

/// One counted inbound connection; dropping it frees the slot.
struct InboundConnectionSlot {
    counts: Arc<InboundConnectionCounts>,
    peer: PeerId,
}

impl InboundConnectionCounts {
    /// A slot for a new connection from `peer`, or `None` at the cap.
    fn try_acquire(self: &Arc<Self>, peer: PeerId) -> Option<InboundConnectionSlot> {
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let held = open.entry(peer).or_insert(0);
        if *held >= MAX_INBOUND_CONNECTIONS_PER_PEER {
            return None;
        }
        *held += 1;
        Some(InboundConnectionSlot { counts: Arc::clone(self), peer })
    }
}

impl Drop for InboundConnectionSlot {
    fn drop(&mut self) {
        let mut open = self.counts.open.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(held) = open.get_mut(&self.peer) {
            *held -= 1;
            if *held == 0 {
                open.remove(&self.peer);
            }
        }
    }
}

#[derive(Debug, Clone)]
struct YadoriProtocolHandler {
    inbound: Arc<mpsc::Sender<PeerLink>>,
    admission: Arc<dyn crate::PeerAdmission>,
    observer: Option<crate::observe::LinkObserver>,
    connections: Arc<InboundConnectionCounts>,
}

impl iroh::protocol::ProtocolHandler for YadoriProtocolHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let remote = connection.remote_id();
        let peer = PeerId::from_bytes(*remote.as_bytes());

        // Authenticated is not authorized. The handshake that got us here
        // proves only that the remote holds this key; whether the key is
        // one of ours is a question iroh cannot answer and this must.
        // Refuse before a link exists, so there is no window in which an
        // unauthorized peer holds one.
        if !self.admission.admit(&peer) {
            // A close code, not a silent drop: the peer learns the ALPN
            // spoke and declined, which is what an honest client needs to
            // stop retrying. It reveals nothing a dialer did not already
            // know, since reaching this point required the address.
            connection.close(REFUSED_UNAUTHORIZED.into(), b"unauthorized device");
            tracing::debug!(?peer, "refused an inbound sync connection from an unpinned device");
            return Ok(());
        }

        let Some(_slot) = self.connections.try_acquire(peer) else {
            connection.close(REFUSED_TOO_MANY_CONNECTIONS.into(), b"too many connections");
            tracing::debug!(?peer, "refused an inbound sync connection beyond the per-peer cap");
            return Ok(());
        };

        let link = PeerLink::new(peer, connection.clone());
        if let Some(observer) = &self.observer {
            observer.notify(crate::observe::LinkEvent::Accepted(&link));
        }

        if self.inbound.send(link).await.is_err() {
            // The substrate is shutting down; nothing will service this link.
            connection.close(0u32.into(), b"shutting down");
            return Ok(());
        }

        // Hold the connection open for as long as the protocol layer uses it.
        // Returning here would drop iroh's side of the connection.
        connection.closed().await;
        Ok(())
    }
}

#[cfg(test)]
mod relay_config_tests;

#[cfg(test)]
mod connection_cap_tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    /// One peer cannot hold more than the cap; another peer is unaffected, and
    /// a closed connection frees its slot.
    #[test]
    fn a_peer_cannot_hold_more_inbound_connections_than_the_cap() {
        let counts = Arc::new(InboundConnectionCounts::default());
        let held: Vec<_> = (0..MAX_INBOUND_CONNECTIONS_PER_PEER)
            .map(|_| counts.try_acquire(peer(1)).expect("within the cap"))
            .collect();
        assert!(counts.try_acquire(peer(1)).is_none(), "the next one is over the cap");
        assert!(counts.try_acquire(peer(2)).is_some(), "another peer has its own allowance");
        drop(held);
        assert!(counts.try_acquire(peer(1)).is_some(), "closed connections free their slots");
    }
}
