//! A single peer connection, multiplexed into independent lane streams.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::SubstrateError;
use crate::lane::{Lane, LaneLimits};
use crate::peer::PeerId;

/// Holds a lane's concurrency slot for as long as any half of its stream is
/// alive. Shared so that splitting a stream does not silently release it.
type LaneSlot = Arc<LanePermit>;

/// One stream belonging to a lane class.
///
/// The lane tag has already been exchanged, so the first byte a caller reads
/// or writes is protocol payload. Dropping the stream returns its slot to the
/// lane's concurrency budget.
#[derive(Debug)]
pub struct LaneStream {
    lane: Lane,
    send: LaneSend,
    recv: LaneRecv,
}

impl LaneStream {
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// Split into independently owned halves. Both keep the lane's concurrency
    /// slot reserved until the last of them is dropped.
    pub fn split(self) -> (LaneSend, LaneRecv) {
        (self.send, self.recv)
    }

    /// Signal that nothing further will be written on this stream.
    pub fn finish(&mut self) -> Result<(), SubstrateError> {
        self.send.finish()
    }
}

impl LaneStream {
    fn assemble(
        lane: Lane,
        send: iroh::endpoint::SendStream,
        recv: iroh::endpoint::RecvStream,
        slot: LanePermit,
    ) -> Self {
        let slot: LaneSlot = Arc::new(slot);
        Self {
            lane,
            send: LaneSend { lane, inner: send, _slot: slot.clone() },
            recv: LaneRecv { lane, inner: recv, _slot: slot },
        }
    }
}

impl AsyncRead for LaneStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for LaneStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// The writing half of a lane stream.
#[derive(Debug)]
pub struct LaneSend {
    lane: Lane,
    inner: iroh::endpoint::SendStream,
    _slot: LaneSlot,
}

impl LaneSend {
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// Signal that nothing further will be written on this stream.
    pub fn finish(&mut self) -> Result<(), SubstrateError> {
        self.inner
            .finish()
            .map_err(|err| SubstrateError::LaneIo { lane: self.lane, reason: err.to_string() })
    }
}

impl AsyncWrite for LaneSend {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

/// The reading half of a lane stream.
#[derive(Debug)]
pub struct LaneRecv {
    lane: Lane,
    inner: iroh::endpoint::RecvStream,
    _slot: LaneSlot,
}

impl LaneRecv {
    pub fn lane(&self) -> Lane {
        self.lane
    }
}

impl AsyncRead for LaneRecv {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.inner), cx, buf)
    }
}

/// Which kind of network path is carrying a connection's traffic.
///
/// An observation, never an authorization input. `verify_proof_carrying_change`
/// takes no parameter naming a carrier, and nothing here may become one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// Through a relay server.
    Relay,
    /// Endpoint to endpoint.
    Direct,
}

/// The kind of the selected path of `connection`, if one is selected.
fn carrier_of(connection: &iroh::endpoint::Connection) -> Option<Carrier> {
    connection.paths().iter().find(|path| path.is_selected()).map(|path| {
        if path.is_relay() {
            Carrier::Relay
        } else {
            Carrier::Direct
        }
    })
}

/// The carrier of one connection, reported each time its paths change, until
/// the connection is gone. See [`PeerLink::carrier_changes`].
#[derive(Debug)]
pub struct CarrierChanges {
    events: iroh::endpoint::PathEventStream,
    connection: iroh::endpoint::WeakConnectionHandle,
    /// The carrier when following started, reported first.
    first: Option<Option<Carrier>>,
}

impl CarrierChanges {
    /// The carrier now: at once the first time, then after the next change
    /// to the connection's paths. `None` once the connection has closed or
    /// been dropped; after that it never reports again.
    ///
    /// A change reports the carrier as it stands when it is read rather than
    /// what the event said, so an event missed by a slow reader costs
    /// nothing: the next read is current anyway.
    pub async fn next(&mut self) -> Option<Option<Carrier>> {
        use n0_future::StreamExt as _;

        if let Some(first) = self.first.take() {
            return Some(first);
        }
        self.events.next().await?;
        let connection = self.connection.upgrade()?;
        if connection.close_reason().is_some() {
            return None;
        }
        Some(carrier_of(&connection))
    }
}

/// How long a stream the peer opened may take to send its one-byte lane tag.
pub const LANE_TAG_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// A stream the remote side opened whose lane tag has not been read yet; see
/// [`PeerLink::accept_stream`].
#[derive(Debug)]
pub struct InboundStream {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

/// An established connection to one peer.
///
/// A link is cheap to clone; clones share the underlying QUIC connection and
/// the per-lane concurrency budgets.
#[derive(Debug, Clone)]
pub struct PeerLink {
    peer: PeerId,
    connection: iroh::endpoint::Connection,
    budgets: Arc<HashMap<Lane, Arc<FairLaneGate>>>,
}

impl PeerLink {
    /// Watches which network paths carry this connection, from now on.
    ///
    /// Subscribe BEFORE any transfer. The stream reports paths opening and
    /// closing, and a closing path carries its final byte count -- the only
    /// place those numbers survive, since a closed path is absent from every
    /// later snapshot. Reading paths at the end instead would report a
    /// relay-then-direct connection as direct only, which is precisely the
    /// false negative a benchmark cannot afford.
    ///
    /// Ask the returned watcher for its verdict when the TRANSFER ends, not
    /// when the connection does: a benchmark wants to know what carried its
    /// bytes while the connection is still up, and waiting for close would also
    /// mean holding the connection open to be able to ask.
    pub fn watch_paths(&self) -> PathWatcher {
        use n0_future::StreamExt as _;

        // Subscribe FIRST, then read the existing paths: the other order would
        // miss a path that opened in between.
        let events = self.connection.path_events();
        // Paths that already exist have emitted their `Opened` to nobody -- the
        // initial path is registered before the receiver is handed out, and on
        // a relay-mode dial that path IS the relay. Seeding is the only way it
        // can ever be reported.
        let seed: Vec<(iroh::endpoint::PathId, crate::PathKind)> = self
            .connection
            .paths()
            .iter()
            .map(|path| (path.id(), kind_of(path.remote_addr())))
            .collect();
        // Mapped into this crate's own vocabulary at the edge, so the ordering
        // rule is testable without a network: iroh's `PathEvent` is
        // `#[non_exhaustive]` and cannot be constructed by a test.
        let updates = events.filter_map(map_event);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let pump =
            tokio::spawn(crate::path_witness::pump_updates(Box::pin(updates), stop_rx, seed));

        PathWatcher { stop: stop_tx, pump, connection: self.connection.clone() }
    }

    pub(crate) fn new(peer: PeerId, connection: iroh::endpoint::Connection) -> Self {
        Self::with_limits(peer, connection, LaneLimits::default())
    }

    pub(crate) fn with_limits(
        peer: PeerId,
        connection: iroh::endpoint::Connection,
        limits: LaneLimits,
    ) -> Self {
        let budgets = Lane::ALL
            .into_iter()
            .map(|lane| (lane, Arc::new(FairLaneGate::new(lane, limits.for_lane(lane)))))
            .collect();

        Self { peer, connection, budgets: Arc::new(budgets) }
    }

    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Whether this connection is still usable.
    ///
    /// A cached link is worth reusing only while it is alive; a closed one is
    /// redialled rather than handed out to fail on first use.
    pub fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// Open a stream in `lane` as the initiating side.
    ///
    /// A lane is a class, not a single stream: several block or service
    /// transfers run concurrently, up to that lane's budget. Opening blocks
    /// only on the lane's own budget — an already-open stream that is stalled,
    /// saturated or waiting on storage never delays a different lane, which is
    /// the property the single shared control stream did not have.
    pub async fn open_lane(&self, lane: Lane) -> Result<LaneStream, SubstrateError> {
        self.open_lane_for(lane, "").await
    }

    /// As [`Self::open_lane`], saying which class of work the stream carries.
    ///
    /// The lane's budget is shared out BETWEEN classes rather than in arrival
    /// order -- see [`FairLaneGate`] for the measurement that made this
    /// necessary. Callers that have a meaningful class (a folder group, for
    /// block transfers) should name it; the rest share one.
    pub async fn open_lane_for(
        &self,
        lane: Lane,
        class: &str,
    ) -> Result<LaneStream, SubstrateError> {
        let slot = self.reserve(lane, class).await?;

        let (mut send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|err| SubstrateError::Lane { lane, reason: err.to_string() })?;

        // Announce which lane class this stream carries, so the peer can
        // dispatch it before any payload arrives.
        tokio::io::AsyncWriteExt::write_all(&mut send, &[lane.tag()])
            .await
            .map_err(|err| SubstrateError::Lane { lane, reason: err.to_string() })?;

        Ok(LaneStream::assemble(lane, send, recv, slot))
    }

    /// Accept the next stream the remote side opens, on whichever lane.
    ///
    /// Reads the lane tag and takes a budget slot before returning, so a
    /// serial caller is held up by a stream that never sends its tag (bounded
    /// by [`LANE_TAG_DEADLINE`]) or by a full lane budget. A server that must
    /// keep accepting while one stream waits uses [`Self::accept_stream`] and
    /// finishes each stream with [`Self::identify_stream`] in its own task.
    pub async fn accept_lane(&self) -> Result<LaneStream, SubstrateError> {
        let stream = self.accept_stream().await?;
        self.identify_stream(stream).await
    }

    /// Accept the next stream the remote side opens without reading anything
    /// from it. An error here means the connection itself ended.
    pub async fn accept_stream(&self) -> Result<InboundStream, SubstrateError> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|err| SubstrateError::Accept { reason: err.to_string() })?;
        Ok(InboundStream { send, recv })
    }

    /// Reads `stream`'s lane tag, within [`LANE_TAG_DEADLINE`], and takes its
    /// lane's budget slot. An error here is about this one stream only; the
    /// connection is unaffected.
    pub async fn identify_stream(
        &self,
        stream: InboundStream,
    ) -> Result<LaneStream, SubstrateError> {
        let InboundStream { send, mut recv } = stream;
        let mut tag = [0u8; 1];
        tokio::time::timeout(
            LANE_TAG_DEADLINE,
            tokio::io::AsyncReadExt::read_exact(&mut recv, &mut tag),
        )
        .await
        .map_err(|_| SubstrateError::Accept { reason: "no lane tag within the deadline".into() })?
        .map_err(|err| SubstrateError::Accept { reason: err.to_string() })?;

        let lane = Lane::from_tag(tag[0]).ok_or(SubstrateError::UnknownLaneTag(tag[0]))?;
        // One class on the accepting side: the lane tag is all that has
        // arrived so far, and the group is not in it. What the serving side
        // does with a request once it has read the header is the block-serve
        // scheduler's business, not this budget's.
        let slot = self.reserve(lane, "").await?;

        Ok(LaneStream::assemble(lane, send, recv, slot))
    }

    /// Opens a bidirectional stream and returns it raw, with no lane tag
    /// written, so a test can send a malformed or missing tag.
    #[cfg(feature = "test-support")]
    pub async fn open_raw_stream_for_test(
        &self,
    ) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream), SubstrateError> {
        self.connection
            .open_bi()
            .await
            .map_err(|err| SubstrateError::Accept { reason: err.to_string() })
    }

    /// Which network path this connection is currently sending on.
    ///
    /// A connection normally opens over a relay and gains a direct path once
    /// hole punching succeeds, at which point the selected path changes under
    /// it — the connection itself does not change. That is why this is a
    /// question about a live link rather than something decided at dial time,
    /// and why nothing above this layer may treat "relayed" as an identity: it
    /// is a fact about right now, and admission never consults it at all.
    ///
    /// `None` when no path is selected yet.
    pub fn carrier(&self) -> Option<Carrier> {
        carrier_of(&self.connection)
    }

    /// Follows [`Self::carrier`] for as long as this connection lives,
    /// without keeping it open.
    ///
    /// Subscribes before reading, so a path change between the two is not
    /// lost. Holds only a weak handle: following a connection must not be
    /// what keeps it alive, or a connection its owners dropped would stay up
    /// -- and read as reachable -- because something was watching it.
    pub fn carrier_changes(&self) -> CarrierChanges {
        let events = self.connection.path_events();
        CarrierChanges {
            events,
            connection: self.connection.weak_handle(),
            first: Some(self.carrier()),
        }
    }

    /// Whether a direct path is open at all, selected or not.
    pub fn has_direct_path(&self) -> bool {
        self.connection.paths().iter().any(|path| path.is_ip())
    }

    /// Close the connection. Idempotent.
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"closed");
    }

    /// Whether the connection is still usable.
    pub fn is_open(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    async fn reserve(&self, lane: Lane, class: &str) -> Result<LanePermit, SubstrateError> {
        let gate = self.budgets.get(&lane).expect("every lane has a budget");
        gate.acquire(class).await
    }
}

/// Admission to one lane's concurrency budget, rotated across classes.
///
/// The budget on its own is a single FIFO queue: every waiter is served in
/// arrival order, so a caller that enqueues a hundred requests for one folder
/// group puts a later request for a DIFFERENT group behind all of them. That
/// is not a small unfairness. Measured on a real two-group connection: group
/// B's one small request reached the serving device's block store dead last,
/// at position 97 of 98, while the identical request sent over a second
/// connection landed at position 9. The serving side's own fair scheduler
/// never got the chance to be fair, because the request never left this
/// device.
///
/// So a waiter joins its own class's queue, and a finishing transfer hands
/// its permit to the next class in rotation rather than to the next arrival.
/// Within a class, arrival order still decides.
///
/// The permit is handed over directly instead of being released back to the
/// semaphore, so there is no window in which a fresh caller can take a turn
/// that was already allocated to someone waiting.
#[derive(Debug)]
pub(crate) struct FairLaneGate {
    lane: Lane,
    budget: Arc<Semaphore>,
    state: std::sync::Mutex<GateState>,
}

#[derive(Debug, Default)]
struct GateState {
    /// One queue per class, keyed so rotation has a stable order.
    waiting: std::collections::BTreeMap<String, std::collections::VecDeque<Waiter>>,
    /// The class served most recently. The next turn goes to the first class
    /// after it that has anyone waiting.
    last_served: Option<String>,
}

type Waiter = tokio::sync::oneshot::Sender<OwnedSemaphorePermit>;

impl FairLaneGate {
    fn new(lane: Lane, budget: usize) -> Self {
        Self {
            lane,
            budget: Arc::new(Semaphore::new(budget)),
            state: std::sync::Mutex::new(GateState::default()),
        }
    }

    /// A slot in this lane for `class`, waiting for this class's turn.
    async fn acquire(self: &Arc<Self>, class: &str) -> Result<LanePermit, SubstrateError> {
        let receiver = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            // Taking a free slot ahead of anyone already waiting would be the
            // same queue-jumping this gate exists to prevent, so the fast path
            // is only open while nobody is waiting at all.
            if state.waiting.values().all(std::collections::VecDeque::is_empty) {
                if let Ok(permit) = self.budget.clone().try_acquire_owned() {
                    return Ok(LanePermit { gate: self.clone(), permit: Some(permit) });
                }
            }
            let (sender, receiver) = tokio::sync::oneshot::channel();
            state.waiting.entry(class.to_string()).or_default().push_back(sender);
            receiver
        };
        // Dropping this future leaves a dead sender in the queue; the next
        // handover skips it. Nothing is lost, because nothing was allocated
        // to it yet.
        let permit = receiver.await.map_err(|_| SubstrateError::Lane {
            lane: self.lane,
            reason: "lane budget closed".to_owned(),
        })?;
        Ok(LanePermit { gate: self.clone(), permit: Some(permit) })
    }

    /// Give `permit` to the next class in rotation, or let it go.
    fn hand_on(&self, mut permit: OwnedSemaphorePermit) {
        loop {
            let waiter = {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                match state.take_next_in_rotation() {
                    Some(waiter) => waiter,
                    // Nobody waiting: releasing it is what makes it available
                    // to the fast path.
                    None => return,
                }
            };
            match waiter.send(permit) {
                Ok(()) => return,
                // That waiter gave up between joining the queue and now. Its
                // turn passes to whoever is next.
                Err(returned) => permit = returned,
            }
        }
    }
}

impl GateState {
    /// The next waiter, from the first class after the one served last.
    fn take_next_in_rotation(&mut self) -> Option<Waiter> {
        let classes: Vec<String> = self
            .waiting
            .iter()
            .filter(|(_, queue)| !queue.is_empty())
            .map(|(class, _)| class.clone())
            .collect();
        if classes.is_empty() {
            return None;
        }
        let start = match &self.last_served {
            // `partition_point` lands just past the last class served, which
            // is where the next turn begins -- and it is still correct when
            // that class has since left the queue entirely.
            Some(last) => classes.partition_point(|class| class <= last) % classes.len(),
            None => 0,
        };
        let class = classes[start].clone();
        let waiter = self
            .waiting
            .get_mut(&class)
            .and_then(std::collections::VecDeque::pop_front)
            .expect("only classes with a non-empty queue are considered");
        self.last_served = Some(class);
        Some(waiter)
    }
}

/// One held slot in a lane.
///
/// Dropping it hands the slot to the next class waiting, rather than simply
/// returning it -- see [`FairLaneGate`].
#[derive(Debug)]
pub struct LanePermit {
    gate: Arc<FairLaneGate>,
    /// `None` only while dropping.
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for LanePermit {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.gate.hand_on(permit);
        }
    }
}

/// A running observation of one connection's network paths.
///
/// Holds a connection handle, so a benchmark must take its verdict rather than
/// leaving it running -- otherwise the watcher itself keeps the connection
/// alive and nothing ever closes.
pub struct PathWatcher {
    stop: tokio::sync::oneshot::Sender<()>,
    pump: tokio::task::JoinHandle<crate::path_witness::WitnessAccumulator<iroh::endpoint::PathId>>,
    connection: iroh::endpoint::Connection,
}

impl PathWatcher {
    /// Stops watching and reports what the paths carried.
    ///
    /// Folds in the paths still open right now: those have emitted no close
    /// event, so this snapshot is the only place their bytes appear. Paths that
    /// closed earlier were already counted from their close events, which is
    /// what makes the total cover the connection's whole life rather than its
    /// last moment.
    pub async fn finish(self) -> crate::PathWitness {
        // Snapshot FIRST, and that order is the point.
        //
        // Draining before snapshotting leaves a window: the pump finishes, the
        // relay path then closes, its `Closed` reaches nobody, and the path is
        // also gone from the snapshot taken afterwards -- a false "direct only"
        // with nothing marking it incomplete. Taking the snapshot first fixes
        // the transfer-end boundary before anything can move.
        //
        // Every case is then covered, and the dedupe is what lets them overlap
        // safely:
        //   closed before the snapshot   -> counted from its `Closed` event
        //   open at the snapshot         -> counted from the snapshot
        //   closed after, `Closed` drained -> already counted, dedupe ignores it
        //   closed after, `Closed` missed  -> the snapshot's bytes stand
        let snapshot: Vec<(iroh::endpoint::PathId, crate::PathKind, crate::PathBytes)> = self
            .connection
            .paths()
            .iter()
            .map(|path| {
                let stats = path.stats();
                (
                    path.id(),
                    kind_of(path.remote_addr()),
                    // Both directions: on a fetching node the payload is
                    // entirely RX, so a TX-only reading would measure the
                    // acknowledgements and call it the transfer.
                    crate::PathBytes::new(stats.udp_tx.bytes, stats.udp_rx.bytes),
                )
            })
            .collect();

        let _ = self.stop.send(());
        let mut acc = match self.pump.await {
            Ok(acc) => acc,
            Err(_) => {
                // The pump died. Its history is unrecoverable, and a partial
                // total presented as a measurement is the failure mode this
                // type exists to avoid.
                let mut acc = crate::path_witness::WitnessAccumulator::default();
                acc.lagged();
                acc
            }
        };
        for (path, kind, bytes) in snapshot {
            acc.still_open(path, kind, bytes);
        }
        acc.finish()
    }
}

/// Whether a remote transport address is a direct IP path or a relay.
fn kind_of(addr: &iroh::TransportAddr) -> crate::PathKind {
    match addr {
        iroh::TransportAddr::Ip(_) => crate::PathKind::Direct,
        iroh::TransportAddr::Relay(_) => crate::PathKind::Relay,
        // Counted apart rather than folded into either, so a path type added
        // later cannot be silently reported as direct.
        _ => crate::PathKind::Other,
    }
}

/// Translates one iroh path event into this crate's own vocabulary.
fn map_event(
    event: iroh::endpoint::PathEvent,
) -> Option<crate::path_witness::PathUpdate<iroh::endpoint::PathId>> {
    use crate::path_witness::PathUpdate;
    Some(match event {
        iroh::endpoint::PathEvent::Opened { id, remote_addr, .. } => {
            PathUpdate::Opened { path: id, kind: kind_of(&remote_addr) }
        }
        iroh::endpoint::PathEvent::Closed { id, remote_addr, last_stats, .. } => {
            PathUpdate::Closed {
                path: id,
                kind: kind_of(&remote_addr),
                bytes: crate::PathBytes::new(last_stats.udp_tx.bytes, last_stats.udp_rx.bytes),
            }
        }
        iroh::endpoint::PathEvent::Lagged { .. } => PathUpdate::Lagged,
        _ => PathUpdate::Selected,
    })
}
