//! Owning the substrate endpoint and routing inbound lane streams.

use std::sync::Arc;

use tokio::task::JoinHandle;
use yadorilink_sync_protocol::ports::GroupId;
use yadorilink_sync_protocol::session::accept_lane;
use yadorilink_sync_protocol::{ProtocolError, WireError};
use yadorilink_sync_substrate::{
    Lane, LaneStream, PeerAddress, PeerId, PeerLink, SubstrateError, SubstrateNode,
};

/// The task [`SyncRuntime::serve`] returns.
///
/// Named here so a caller can hold it without naming `tokio` itself.
pub type ServeHandle = JoinHandle<()>;

#[derive(Debug, thiserror::Error)]
pub enum SyncRuntimeError {
    #[error(transparent)]
    Substrate(#[from] SubstrateError),

    /// A dial did not finish inside its deadline.
    #[error("connect timed out after {seconds}s")]
    NetworkTimeout { stage: &'static str, seconds: u64 },
}

const CONNECT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Notified with each link this runtime dials, before any lane is
/// opened on it.
///
/// Exists because a reconciliation's link is not reachable any other way.
/// `sync_once` dials its own connection and drops it when the pass ends;
/// `SubstrateNode::connect` and `SyncStack::link_to` both hand out a
/// *different* one, so anything asking "which path did that transfer
/// use?" from outside is answering about a connection the transfer never
/// touched. Observing has to happen here or not at all.
///
/// Two limits a measurement has to respect. This observes links that are
/// *dialled*, so an inbound connection this node accepted is not offered
/// here -- for the question "which carrier moved the payload" that no
/// longer matters, because a witness counts both directions of the link
/// it is on, but a caller wanting every connection to a peer still has to
/// account for accepted ones separately. And `SyncStack::link_to` returns
/// a cached link without dialling when one is already alive, so a hook
/// installed after a link exists never sees it: a measurement must start
/// from a cold daemon, before any reconciliation or bulk link has been
/// opened, or it will silently be reusing an unwatched connection.
///
/// Called for *every* link this runtime dials, before its first lane
/// opens. Both halves matter: subscribing before the first lane is what
/// lets a [`PathWatcher`](yadorilink_sync_substrate::PathWatcher) cover a
/// transfer whole rather than from whenever it happened to start, and
/// seeing every link is what stops it from covering one connection's
/// traffic and being read as the total. Reconciliation and the bulk lanes
/// dial separately, so a peer's traffic is spread over more than one
/// connection.
pub type DialedLinkHook = Arc<dyn Fn(&PeerLink) + Send + Sync>;

/// Notified with each link this runtime *accepted* -- the other half of
/// [`DialedLinkHook`]'s own explicit limit: "an inbound connection this node
/// accepted is not offered here... a caller wanting every connection to a
/// peer still has to account for accepted ones separately."
///
/// Found necessary live, not designed in advance: the 1 GiB direct-path
/// canary's path-witness tool watched only dialled links on each side, so
/// the side that already held the content (never having to dial the bulk
/// connection the other side pulled it over) reported almost no bytes and a
/// `not_direct` verdict for a transfer that was, in fact, entirely direct --
/// correct only because the OTHER side happened to be checked too. A witness
/// that watches only one direction cannot be trusted alone for a pass/fail
/// gate: it can read a genuine direct transfer as a failure whenever this
/// node is the one being pulled from rather than the one pulling.
pub type AcceptedLinkHook = Arc<dyn Fn(&PeerLink) + Send + Sync>;

type BoxFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Handles a stream on a lane this crate does not own.
///
/// Blocks and service RPCs ride their own lanes for flow-control reasons, but
/// neither protocol belongs here. A stream on either is handed over whole,
/// with the peer and the group its hello named.
pub type LaneStreamHook = Arc<dyn Fn(PeerId, GroupId, Lane, LaneStream) -> BoxFuture + Send + Sync>;

/// Told that a peer opened a lane whose hello speaks another protocol version: `(peer, theirs,
/// ours)`.
///
/// The peer completed the transport, so it is reachable; it just cannot sync. Without this the
/// mismatch would only be a debug log and the peer would read as healthy or offline.
pub type IncompatibleLaneHook = Arc<dyn Fn(PeerId, u32, u32) + Send + Sync>;

/// Owns the transport endpoint and routes what arrives on it.
pub struct SyncRuntime {
    node: SubstrateNode,
    /// Shared and read live: the hook is installed after `serve` has already
    /// started, so a task holding a snapshot would hold `None` for good.
    lanes: Arc<std::sync::Mutex<Option<LaneStreamHook>>>,
    dialed: Arc<std::sync::Mutex<Option<DialedLinkHook>>>,
    accepted: Arc<std::sync::Mutex<Option<AcceptedLinkHook>>>,
    incompatible: Arc<std::sync::Mutex<Option<IncompatibleLaneHook>>>,
    /// Milliseconds so it fits an `AtomicU64`; per-instance so a test that
    /// shortens it cannot affect another runtime in the same process.
    connect_deadline_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl SyncRuntime {
    pub fn new(node: SubstrateNode) -> Self {
        Self {
            node,
            lanes: Arc::new(std::sync::Mutex::new(None)),
            dialed: Arc::new(std::sync::Mutex::new(None)),
            accepted: Arc::new(std::sync::Mutex::new(None)),
            incompatible: Arc::new(std::sync::Mutex::new(None)),
            connect_deadline_ms: Arc::new(std::sync::atomic::AtomicU64::new(
                CONNECT_DEADLINE.as_millis() as u64,
            )),
        }
    }

    /// Test-only: this instance's own connect deadline.
    pub fn set_connect_deadline_for_tests(&self, deadline: std::time::Duration) {
        self.connect_deadline_ms
            .store(deadline.as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    fn connect_deadline(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.connect_deadline_ms.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Say who sees each link this runtime dials. See [`DialedLinkHook`].
    pub fn when_link_dialed(&self, hook: DialedLinkHook) {
        *self.dialed.lock().expect("dialed hook poisoned") = Some(hook);
    }

    /// Say who sees each link this runtime accepts. See [`AcceptedLinkHook`].
    pub fn when_link_accepted(&self, hook: AcceptedLinkHook) {
        *self.accepted.lock().expect("accepted hook poisoned") = Some(hook);
    }

    /// Say who hears of a peer whose lane hello speaks another protocol version. See
    /// [`IncompatibleLaneHook`].
    pub fn when_lane_incompatible(&self, hook: IncompatibleLaneHook) {
        *self.incompatible.lock().expect("incompatible hook poisoned") = Some(hook);
    }

    /// Say who handles a stream on a lane this crate does not own.
    pub fn when_lane_stream(&self, hook: LaneStreamHook) {
        *self.lanes.lock().expect("lane hook poisoned") = Some(hook);
    }

    pub fn peer_id(&self) -> PeerId {
        self.node.peer_id()
    }

    /// Dial a peer and show the link to the observer, if any, before it has
    /// carried anything.
    pub async fn connect(&self, peer: PeerId) -> Result<PeerLink, SyncRuntimeError> {
        let deadline = self.connect_deadline();
        let link = match tokio::time::timeout(deadline, self.node.connect(peer)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(SyncRuntimeError::NetworkTimeout {
                    stage: "connect",
                    seconds: deadline.as_secs(),
                })
            }
        };
        let hook = self.dialed.lock().expect("dialed hook poisoned").clone();
        if let Some(hook) = hook {
            hook(&link);
        }
        Ok(link)
    }

    pub fn local_address(&self) -> PeerAddress {
        self.node.local_address()
    }

    /// Close this node's substrate endpoint and every connection on it.
    ///
    /// Must be awaited while the runtime the endpoint's own tasks were spawned
    /// on is still running -- see [`SubstrateNode::shutdown`].
    pub async fn shutdown(&self) {
        self.node.shutdown().await;
    }

    /// This node's address, updated as the substrate learns more of it.
    pub fn watch_local_address(&self) -> tokio::sync::watch::Receiver<PeerAddress> {
        self.node.watch_local_address()
    }

    /// Serve the lane streams the peer opens on a connection THIS side dialled.
    ///
    /// A link is symmetric: either end may open streams on it. Which of a
    /// pair's connections a device opens its own lanes on is decided by its
    /// link cache, and that can be the connection the peer dialled; the peer
    /// then has to answer on the connection it dialled, not only on the ones
    /// it accepted. Ends with the connection.
    pub fn serve_dialed(&self, link: &PeerLink) {
        let (lanes, incompatible, link) =
            (self.lanes.clone(), self.incompatible.clone(), link.clone());
        tokio::spawn(async move { serve_link(link, lanes, incompatible).await });
    }

    /// Serve inbound connections for as long as the returned task lives.
    ///
    /// Each accepted connection gets its own task, and each lane stream within
    /// it gets its own task, so a peer that stalls one lane stalls only that
    /// lane.
    pub fn serve(&self, mut inbound: tokio::sync::mpsc::Receiver<PeerLink>) -> ServeHandle {
        let lanes = self.lanes.clone();
        let accepted = self.accepted.clone();
        let incompatible = self.incompatible.clone();
        tokio::spawn(async move {
            while let Some(link) = inbound.recv().await {
                if let Some(hook) = accepted.lock().expect("accepted hook poisoned").clone() {
                    hook(&link);
                }
                let lanes = lanes.clone();
                let incompatible = incompatible.clone();
                tokio::spawn(async move { serve_link(link, lanes, incompatible).await });
            }
        })
    }
}

/// How long an accepted lane stream may take to send its hello naming a group.
const LANE_HELLO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Accept lane streams from one peer until the connection ends.
///
/// The accept loop only accepts: the lane tag, the lane's budget slot and the
/// hello are all read inside each stream's own task, so one stream that stalls
/// or is malformed costs that stream alone, and a full block lane cannot keep a
/// service stream from being accepted. Only an error accepting a stream, which
/// means the connection ended, stops the loop.
async fn serve_link(
    link: PeerLink,
    lanes: Arc<std::sync::Mutex<Option<LaneStreamHook>>>,
    incompatible: Arc<std::sync::Mutex<Option<IncompatibleLaneHook>>>,
) {
    let peer = link.peer();

    while let Ok(stream) = link.accept_stream().await {
        let lanes = lanes.clone();
        let incompatible = incompatible.clone();
        let link = link.clone();
        tokio::spawn(async move {
            let mut lane = match link.identify_stream(stream).await {
                Ok(lane) => lane,
                Err(error) => {
                    tracing::debug!(%peer, %error, "peer opened a stream without a usable lane tag");
                    return;
                }
            };
            let kind = lane.lane();
            let group = match tokio::time::timeout(LANE_HELLO_DEADLINE, accept_lane(&mut lane))
                .await
            {
                Ok(Ok(group)) => group,
                Ok(Err(error)) => {
                    if let ProtocolError::Wire(WireError::UnsupportedVersion { theirs, ours }) =
                        &error
                    {
                        tracing::warn!(%peer, theirs, ours, "peer speaks another protocol version; its lane is refused");
                        let hook = incompatible.lock().expect("incompatible hook poisoned").clone();
                        if let Some(hook) = hook {
                            hook(peer, *theirs, *ours);
                        }
                    } else {
                        tracing::debug!(%peer, ?kind, %error, "peer opened a lane without a usable hello");
                    }
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, ?kind, "peer opened a lane and sent no hello in time");
                    return;
                }
            };
            let hook = lanes.lock().expect("lane hook poisoned").clone();
            match hook {
                Some(hook) => hook(peer, group, kind, lane).await,
                None => tracing::debug!(%peer, ?kind, "no handler for this lane; closing"),
            }
        });
    }
}

#[cfg(test)]
mod serve_link_tests;
