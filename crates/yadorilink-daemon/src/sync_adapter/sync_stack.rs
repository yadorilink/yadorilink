//! Assembling the reconciliation stack from this device's own state.
//!
//! ```text
//!   netmap                         who a peer is, what they may be told,
//!     │                            where to reach them
//!     ▼
//!   SyncStack
//!     ├─ IrohEndpoint              iroh, identified by the device signing key,
//!     │                            bound by PeerConnectivityRuntime; also
//!     │                            answers Track Send, served elsewhere
//!     └─ SyncRuntime               dials peers, routes inbound lane streams
//! ```

use std::sync::Arc;

use yadorilink_sync_runtime::SyncRuntime;
use yadorilink_sync_substrate::{Lane, NetworkConfig, PeerAddress, PeerId, PeerLink};

use crate::daemon_state::DaemonState;
use crate::peer_connectivity_runtime::IrohEndpoint;

use yadorilink_lane_ports::LaneBlockStream;
use yadorilink_lane_ports::LaneServiceStream;

#[derive(Debug, thiserror::Error)]
pub enum SyncStackError {
    #[error("this device has no signing key, so it has no transport identity")]
    NoDeviceIdentity,

    #[error(transparent)]
    Substrate(#[from] yadorilink_sync_substrate::SubstrateError),

    #[error(transparent)]
    Runtime(#[from] yadorilink_sync_runtime::SyncRuntimeError),

    #[error("the netmap carries no address for {0}, so it cannot be dialled")]
    Unreachable(String),
}

/// The reconciliation stack, running.
pub struct SyncStack {
    runtime: Arc<SyncRuntime>,
    /// This device's iroh endpoint: admission, address lookup, the per-peer
    /// link cache and endpoint-id resolution. Bound by the connectivity
    /// runtime and held here so the endpoint lives exactly as long as the
    /// stack that drives it.
    endpoint: IrohEndpoint,
    state: Arc<DaemonState>,
    serving: yadorilink_sync_runtime::ServeHandle,
    /// Test-only: makes every outbound dial of the link cache run to its
    /// deadline (never finish), as one toward an unreachable address does.
    #[cfg(test)]
    pub(crate) dials_hang: Arc<std::sync::atomic::AtomicBool>,
    /// Test-only: makes every outbound dial fail at once (a refused connect).
    #[cfg(test)]
    pub(crate) dials_fail: Arc<std::sync::atomic::AtomicBool>,
}

impl SyncStack {
    /// Start the stack for `state`.
    ///
    /// The endpoint identity is this device's signing key, so the netmap
    /// already publishes the binding peers need to recognise it — see
    /// `SubstrateNode::spawn_as_device`.
    pub async fn spawn(
        state: Arc<DaemonState>,
        config: NetworkConfig,
    ) -> Result<Self, SyncStackError> {
        Self::spawn_offering(state, config, crate::nas_admin::offered()).await
    }

    /// [`Self::spawn`], with management of this device offered or not
    /// (`nas_admin::offered` in production), so a test can bind both kinds.
    pub(crate) async fn spawn_offering(
        state: Arc<DaemonState>,
        config: NetworkConfig,
        offer_nas_admin: bool,
    ) -> Result<Self, SyncStackError> {
        let signing_key = state.device_signing_key().ok_or(SyncStackError::NoDeviceIdentity)?;

        // The iroh endpoint, its admission policy and its address lookup are
        // the connectivity runtime's; this stack only drives reconciliation
        // over it.
        let (endpoint, inbound) = state
            .peer_connectivity
            .bind_endpoint(
                signing_key.to_bytes(),
                &state.authority,
                crate::send_transfer::track_send_admission(&state),
                offer_nas_admin.then(|| {
                    Arc::new(crate::nas_admin::AccountDevices::of(&state))
                        as Arc<dyn yadorilink_sync_substrate::NasAdminAuthorizer>
                }),
                config,
            )
            .await?;

        // Native replication connections the endpoint accepts.
        if let Some(native_inbound) = endpoint.take_native_replication_inbound() {
            crate::native_replication_runtime::spawn_inbound(
                Arc::downgrade(&state),
                native_inbound,
            );
        }

        let runtime = Arc::new(SyncRuntime::new(endpoint.node()));
        let serving = runtime.serve(inbound);

        Ok(Self {
            runtime,
            endpoint,
            state,
            serving,
            #[cfg(test)]
            dials_hang: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            dials_fail: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// This device's transport identity, which is also its signing key's
    /// public half — what a peer's netmap already pins for it.
    pub fn peer_id(&self) -> PeerId {
        self.endpoint.peer_id()
    }

    /// The address a peer's netmap should record for this device.
    pub fn local_address(&self) -> PeerAddress {
        self.endpoint.local_address()
    }

    /// This device's address, updated as the substrate learns more of it.
    ///
    /// What the endpoint report publishes has to follow this rather than
    /// sample it: the home relay is assigned after the endpoint binds, so a
    /// report built at startup would advertise no relay at all — and to a peer
    /// that cannot reach this device directly, that is indistinguishable from
    /// this device not existing.
    pub fn watch_local_address(&self) -> tokio::sync::watch::Receiver<PeerAddress> {
        self.endpoint.watch_local_address()
    }

    /// This stack's iroh endpoint, for the connectivity runtime's projection
    /// of recorded peer reachability into its address directory.
    pub(crate) fn endpoint(&self) -> &IrohEndpoint {
        &self.endpoint
    }

    /// Where to reach `device_id`, from the netmap.
    ///
    /// `None` when the netmap has not pinned that device's signing key.
    ///
    /// An endpoint id IS the device's signing key, so this is the whole of the
    /// identity resolution: with no pinned key there is nothing to dial, and
    /// dialling something this device cannot name is not a thing to attempt.
    ///
    /// Deliberately no addresses. Where that endpoint currently answers is the
    /// address lookup's question -- see `yadorilink_sync_substrate::directory`
    /// for why feeding the netmap's candidate list to the substrate could not
    /// work: that list is also the legacy peer-session transport's, the two
    /// speak different protocols on different sockets, and neither consumer
    /// can tell which entry is meant for it.
    pub fn peer_id_of(&self, device_id: &str) -> Option<PeerId> {
        self.endpoint.peer_id_of(device_id)
    }

    /// Route inbound block and service streams to the session that
    /// owns that peer.
    ///
    /// The peer is resolved from its endpoint identity through the netmap on
    /// every stream, never from anything remembered when the connection
    /// opened: a device unpinned since then resolves to nothing and is served
    /// nothing.
    pub fn serve_peer_lanes(self: &Arc<Self>) {
        let stack = Arc::downgrade(self);

        // A peer whose lane hello speaks another protocol version completed the transport: it is
        // online, so it is reported as incompatible, never as offline.
        let incompatible = stack.clone();
        self.runtime.when_lane_incompatible(Arc::new(move |peer, _theirs, _ours| {
            let Some(stack) = incompatible.upgrade() else { return };
            if let Some(device) = stack.state.authority.device_id_for_signing_key(peer.as_bytes()) {
                stack.state.peer_connectivity.record_version_incompatible(&device);
            }
        }));

        self.runtime.when_lane_stream(Arc::new(move |peer, group, lane, stream| {
            let stack = stack.clone();
            Box::pin(async move {
                let Some(stack) = stack.upgrade() else { return };
                let Some(session) = stack.session_for_or_await(&peer, lane).await else {
                    tracing::debug!(?lane, "no session for this peer; closing the stream");
                    return;
                };
                match lane {
                    Lane::Block => {
                        session.serve_block_stream(Box::new(LaneBlockStream::new(stream))).await
                    }
                    Lane::Service => {
                        session
                            .serve_service_stream(
                                group.as_str(),
                                Box::new(LaneServiceStream::new(stream)),
                            )
                            .await
                    }
                }
            })
        }));
    }

    /// The substrate transports for a session reaching `peer_device_id`.
    ///
    /// From here that session's blocks, service RPCs and snapshots ride the
    /// substrate's lanes, and nothing below it knows: the ports were always
    /// the seam. Resolved BEFORE a session is constructed now, not attached
    /// after -- `SessionTransports` is a required constructor parameter (see
    /// its own doc comment), so there is no longer a window in which a
    /// session exists but cannot yet reach its peer, and therefore nothing
    /// left to serialize a backfill against.
    pub fn transports_for(
        self: &Arc<Self>,
        peer_device_id: &str,
    ) -> yadorilink_peer_session::ports::SessionTransports {
        let transports =
            Arc::new(yadorilink_lane_ports::PeerTransports::new(Arc::new(StackLink {
                stack: self.clone(),
                device_id: peer_device_id.to_string(),
            })));
        yadorilink_peer_session::ports::SessionTransports {
            blocks: transports.clone(),
            service: transports.clone(),
        }
    }

    /// [`Self::session_for`], except that a service request which beat its
    /// session to this side waits for the session to be registered. The
    /// asker opens its session first and asks at once (custody confirmation
    /// runs when a session opens), so without the wait the answer would be a
    /// closed stream and the asker would have nothing to retry on until its
    /// periodic sweep. Woken by registration, not polled; the cap only stops
    /// a peer that never gets a session from parking streams.
    async fn session_for_or_await(
        &self,
        peer: &PeerId,
        lane: Lane,
    ) -> Option<Arc<yadorilink_peer_session::peer_session::PeerSyncSession>> {
        let mut registrations = self.state.peers.subscribe_to_registrations();
        if let Some(session) = self.session_for(peer) {
            return Some(session);
        }
        if lane != Lane::Service {
            return None;
        }
        let waited = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                registrations.changed().await.ok()?;
                if let Some(session) = self.session_for(peer) {
                    return Some(session);
                }
            }
        })
        .await;
        waited.ok().flatten()
    }

    /// The live session for this endpoint identity, if the netmap still
    /// attributes it to a device this daemon has one for.
    fn session_for(
        &self,
        peer: &PeerId,
    ) -> Option<Arc<yadorilink_peer_session::peer_session::PeerSyncSession>> {
        let device = self.state.authority.device_id_for_signing_key(peer.as_bytes())?;
        self.state.peers.session(&device)
    }

    /// Say who sees each link a reconciliation dials, before it carries
    /// anything. The only way to witness the path a real transfer took --
    /// see `yadorilink_sync_runtime::DialedLinkHook`.
    pub fn when_link_dialed(&self, hook: yadorilink_sync_runtime::DialedLinkHook) {
        self.runtime.when_link_dialed(hook);
    }

    /// Say who sees each link this stack accepts. The other half of
    /// [`Self::when_link_dialed`] -- see
    /// `yadorilink_sync_runtime::AcceptedLinkHook`.
    pub fn when_link_accepted(&self, hook: yadorilink_sync_runtime::AcceptedLinkHook) {
        self.runtime.when_link_accepted(hook);
    }

    /// Test-only: shortens THIS stack's own reconciliation connect deadline,
    /// so a test with a genuinely unreachable peer does not have to wait out
    /// the full production budget. Per-instance -- see
    /// `yadorilink_sync_runtime::SyncRuntime::set_connect_deadline_for_tests`
    /// for why this is not a process-wide override.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_connect_deadline_for_tests(&self, deadline: std::time::Duration) {
        self.runtime.set_connect_deadline_for_tests(deadline);
    }

    /// Stop serving and close the substrate endpoint.
    ///
    /// A peer learns that this device has gone away from the connection
    /// closing, and from nothing else. Leave the endpoint open and the peer
    /// keeps a connection to a socket nobody answers on any more -- and since
    /// iroh sends every datagram for a remote down that connection's selected
    /// path, including the handshake of a BRAND NEW dial, the peer cannot
    /// reach this device again until that dead connection reaches its own
    /// idle timeout.
    ///
    /// Deliberately not `Drop`: closing is asynchronous, and it has to happen
    /// while the runtime the endpoint's tasks live on is still running.
    pub async fn shutdown(&self) {
        self.serving.abort();
        self.endpoint.shutdown().await;
    }

    /// The connection to `device_id`, dialled if there is not a live one.
    ///
    /// Dialled through this stack's runtime, so the dial is seen by the same
    /// observers as a reconciliation's own; cached by the endpoint.
    pub async fn link_to(&self, device_id: &str) -> Result<Arc<PeerLink>, SyncStackError> {
        self.endpoint
            .link_to_adopting(
                device_id,
                // The peer may open its lanes on this connection (its link
                // cache can pick the connection this side dialled), so it is
                // served like an accepted one -- once the endpoint holds it.
                {
                    let runtime = self.runtime.clone();
                    move |link| runtime.serve_dialed(link)
                },
                {
                    let runtime = self.runtime.clone();
                    #[cfg(test)]
                    let (hang, fail) = (self.dials_hang.clone(), self.dials_fail.clone());
                    move |peer| async move {
                        #[cfg(test)]
                        if hang.load(std::sync::atomic::Ordering::SeqCst) {
                            std::future::pending::<()>().await;
                        }
                        #[cfg(test)]
                        if fail.load(std::sync::atomic::Ordering::SeqCst) {
                            return Err(SyncStackError::Unreachable("refused".to_string()));
                        }
                        runtime.connect(peer).await.map_err(SyncStackError::from)
                    }
                },
            )
            .await?
            .ok_or_else(|| SyncStackError::Unreachable(device_id.to_string()))
    }

    /// Test-only: the runtime dials go through, for a test that has to
    /// count or hold a dial of its own.
    #[cfg(test)]
    pub(crate) fn runtime_for_tests(&self) -> &Arc<SyncRuntime> {
        &self.runtime
    }

    /// Test-only: teach two stacks where the other's substrate answers.
    ///
    /// Production gets this from the coordination plane. Every test fixture
    /// used to do it with `record_peer_candidate_addresses`, which is the
    /// LEGACY peer-session transport's list and no longer reaches
    /// reconciliation -- the two transports listen on different sockets with
    /// different ALPNs, and one list could not serve both. This exists so the
    /// correct wiring has a single name: patching each call site individually
    /// is how the same coupling reappeared in three separate fixtures.
    #[cfg(any(test, feature = "test-support"))]
    pub fn teach_each_other_for_tests(a: &Self, b: &Self) {
        for (from, to) in [(a, b), (b, a)] {
            let address = from.local_address();
            to.address_directory().record(
                address.peer(),
                address.direct_addrs().copied().collect(),
                address.relay_urls().map(ToString::to_string).collect(),
            );
        }
    }

    /// Where this device publishes and resolves substrate endpoint addresses.
    ///
    /// Exposed so the netmap-push path can record a peer's substrate address
    /// as the plane reports it. Deliberately NOT fed from
    /// `peer_candidate_addresses`: that is the legacy transport's list, and
    /// mixing the two is what made both unreachable.
    pub fn address_directory(
        &self,
    ) -> &Arc<super::address_directory::CoordinationAddressDirectory> {
        self.endpoint.address_directory()
    }

    /// The device this endpoint identity belongs to, per the netmap.
    pub fn device_for_peer(&self, peer: &PeerId) -> Option<String> {
        self.endpoint.device_for_peer(peer)
    }
}

impl Drop for SyncStack {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// One peer's connection, resolved through the netmap and this stack's link
/// cache.
///
/// The production answer to [`PeerLinkSource`]: which device, and where the
/// netmap currently says it is. A test dialling a peer it already has an
/// address for answers the same question differently and gets the same
/// transports — that is the point of the trait.
struct StackLink {
    stack: Arc<SyncStack>,
    device_id: String,
}

#[async_trait::async_trait]
impl yadorilink_lane_ports::PeerLinkSource for StackLink {
    async fn link(
        &self,
    ) -> Result<Arc<yadorilink_sync_substrate::PeerLink>, yadorilink_transport::TransportError>
    {
        self.stack
            .link_to(&self.device_id)
            .await
            .map_err(|error| yadorilink_transport::TransportError::NoRoute(error.to_string()))
    }
}
