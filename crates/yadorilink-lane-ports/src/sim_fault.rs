//! Network faults for the simulated substrate, injected at the one place
//! they belong: the datagram carrier.
//!
//! ```text
//! Iroh QUIC
//!   ↓
//! FaultInjectingTransport   ← this module
//!   ↓
//! TestTransport             ← upstream's
//!   ↓
//! TestNetwork               ← upstream's
//! ```
//!
//! Nothing above the carrier knows this exists. `PeerTransports`, the lane
//! streams and every session on top are untouched, which is the point: a
//! fault that a session could see the shape of would be a fault in the test
//! harness, not in the network.
//!
//! # Drop, not hold
//!
//! A partition here *discards* the datagrams it stops. It does not queue
//! them for delivery on heal, and that is a semantic choice rather than an
//! implementation shortcut. A real partition loses packets; QUIC's own loss
//! recovery is what carries a connection across one, and a carrier that
//! replayed a partition's backlog the moment it healed would hide exactly
//! the recovery behaviour these tests exist to exercise. Holding is a
//! different fault with different consequences, and when it is wanted it
//! should be asked for by name.
//!
//! # Wire faults beyond the symmetric cut
//!
//! Three more faults live in the same place, each deterministic from its
//! parameters (no RNG, no wall clock):
//!
//! * a one-way cut ([`SimFaultController::partition_one_way`]): datagrams
//!   `from -> to` are discarded and `to -> from` flow, the shape of a broken
//!   return path or an asymmetric firewall;
//! * duplication ([`SimFaultController::duplicate_datagrams`]): every `n`th
//!   datagram on a directed link is sent twice;
//! * reordering and delay ([`SimFaultController::hold_inbound`]): every `n`th
//!   datagram arriving at an endpoint is held back until `k` later datagrams
//!   have overtaken it, or until the endpoint would otherwise see an idle
//!   wire (so a held datagram is delayed, never lost).
//!
//! Reordering is done on the receive side because a sender cannot hold a
//! datagram: `Transmit` has no public constructor, so the only thing a
//! sender can do with one is forward it now, drop it, or forward it twice.
//! For the same reason the hold policy is per receiving endpoint, not per
//! link: the sender of a received datagram is not readable from `RecvInfo`.
//! Every fault counts what it did, so a test can show it fired.
//!
//! # What a partition does not do
//!
//! It does not close connections, drop state, or tell iroh anything. Both
//! endpoints go on believing the peer is reachable and go on retransmitting
//! into the dark, which is what makes the healed case a real recovery rather
//! than a fresh connection.

#![cfg(feature = "test-support")]

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use iroh::test_utils::test_transport::{TestNetwork, TestTransport, TEST_TRANSPORT_ID};
use iroh_base::CustomAddr;

/// Re-exported, not merely imported: every public method below takes one, and
/// a caller that does not itself depend on iroh could not otherwise name the
/// type it has to pass. `SimFaultController` is reachable through this
/// crate's `test-support` feature, so its argument type has to be too.
pub use iroh::EndpointId;

/// Which links are currently cut, shared by every endpoint on one network.
///
/// One controller per simulated network, not one per endpoint: a partition is
/// a property of the link between two endpoints, and both ends have to agree
/// about it or traffic would flow one way.
#[derive(Clone, Debug, Default)]
pub struct SimFaultController {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Directed pairs: `(from, to)` is a cut when datagrams from `from` to
    /// `to` are discarded. A symmetric partition inserts both directions.
    cut: Mutex<HashSet<(EndpointId, EndpointId)>>,
    /// Directed links that duplicate datagrams, with their phase counter.
    duplicating: Mutex<HashMap<(EndpointId, EndpointId), Duplicate>>,
    /// Receiving endpoints whose inbound datagrams are held back.
    holding: Mutex<HashMap<EndpointId, HoldPolicy>>,
    duplicated: AtomicU64,
    reordered: AtomicU64,
    /// The same evidence per directed link or receiving endpoint, so a fault
    /// is credited only by what happened on its own target.
    dropped_on: Mutex<HashMap<(EndpointId, EndpointId), u64>>,
    duplicated_on: Mutex<HashMap<(EndpointId, EndpointId), u64>>,
    reordered_at: Mutex<HashMap<EndpointId, u64>>,
    /// Every datagram a cut link has discarded, across all links.
    ///
    /// Evidence, not bookkeeping. A test that partitions two endpoints and
    /// then watches a request time out has not distinguished "the partition
    /// stopped it" from "nothing was ever sent"; this counter does.
    dropped: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
struct Duplicate {
    every_nth: u64,
    seed: u64,
    seen: u64,
}

/// Which inbound datagrams are held and for how long. Pure data, so the
/// decision is testable without a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldPolicy {
    /// Every `every_nth` datagram is held (`1` holds all of them).
    pub every_nth: u64,
    /// A held datagram is released once this many later datagrams have been
    /// seen (`1` swaps it with the next one).
    pub release_after: u32,
    /// Shifts which datagram is the first held, so seeds explore different
    /// alignments of the same policy.
    pub seed: u64,
}

/// The receive-side queue behind [`HoldPolicy`], generic over the datagram so
/// the ordering rule is unit-tested without iroh types.
#[derive(Debug)]
struct Shaper<T> {
    seen: u64,
    held: VecDeque<(T, u32, bool)>,
}

impl<T> Default for Shaper<T> {
    fn default() -> Self {
        Self { seen: 0, held: VecDeque::new() }
    }
}

impl<T> Shaper<T> {
    /// One batch of arrivals in; the batch to deliver out, plus how many of
    /// the delivered datagrams were released after a later one overtook them.
    fn shape(&mut self, policy: HoldPolicy, arrivals: Vec<T>) -> (Vec<T>, u64) {
        let mut out = Vec::with_capacity(arrivals.len());
        let mut overtaken = 0;
        for arrival in arrivals {
            let index = self.seen;
            self.seen += 1;
            for (_, remaining, _) in self.held.iter_mut() {
                *remaining = remaining.saturating_sub(1);
            }
            let hold = policy.every_nth > 0
                && policy.release_after > 0
                && index.wrapping_add(policy.seed).is_multiple_of(policy.every_nth);
            if hold {
                self.held.push_back((arrival, policy.release_after, false));
            } else {
                out.push(arrival);
                // A datagram that arrived after these were held is delivered
                // before them: they are now out of order.
                for (_, _, passed) in self.held.iter_mut() {
                    *passed = true;
                }
            }
            while self.held.front().is_some_and(|(_, remaining, _)| *remaining == 0) {
                if let Some((late, _, passed)) = self.held.pop_front() {
                    out.push(late);
                    overtaken += u64::from(passed);
                }
            }
        }
        (out, overtaken)
    }

    /// Everything still held, oldest first: the wire went idle or the policy
    /// was lifted. Also returns how many of them a later datagram had already
    /// overtaken.
    fn drain(&mut self) -> (Vec<T>, u64) {
        let overtaken = self.held.iter().filter(|(_, _, passed)| *passed).count() as u64;
        (self.held.drain(..).map(|(held, _, _)| held).collect(), overtaken)
    }

    fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

impl SimFaultController {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cuts the link between `a` and `b` in both directions.
    ///
    /// Idempotent: cutting an already-cut link is not an error, because a
    /// schedule that fires the same fault twice is a schedule, not a bug.
    pub fn partition(&self, a: EndpointId, b: EndpointId) {
        let mut cut = self.inner.cut.lock().expect("fault controller poisoned");
        cut.insert((a, b));
        cut.insert((b, a));
    }

    /// Cuts only the `from -> to` direction: `from` can no longer reach `to`,
    /// while `to` still reaches `from`. Idempotent.
    pub fn partition_one_way(&self, from: EndpointId, to: EndpointId) {
        self.inner.cut.lock().expect("fault controller poisoned").insert((from, to));
    }

    /// Restores the `from -> to` direction only.
    pub fn heal_one_way(&self, from: EndpointId, to: EndpointId) {
        self.inner.cut.lock().expect("fault controller poisoned").remove(&(from, to));
    }

    /// Whether datagrams from `from` to `to` are discarded.
    pub fn is_cut(&self, from: EndpointId, to: EndpointId) -> bool {
        self.inner.cut.lock().expect("fault controller poisoned").contains(&(from, to))
    }

    /// Sends every `every_nth` datagram from `from` to `to` twice, starting
    /// at the datagram `seed % every_nth`. Replaces any earlier setting for
    /// the link.
    pub fn duplicate_datagrams(&self, from: EndpointId, to: EndpointId, every_nth: u64, seed: u64) {
        assert!(every_nth > 0, "duplication period must be positive");
        self.inner
            .duplicating
            .lock()
            .expect("fault controller poisoned")
            .insert((from, to), Duplicate { every_nth, seed, seen: 0 });
    }

    pub fn stop_duplicating(&self, from: EndpointId, to: EndpointId) {
        self.inner.duplicating.lock().expect("fault controller poisoned").remove(&(from, to));
    }

    /// Holds back inbound datagrams at `at` per `policy` (reordering and
    /// delay). Replaces any earlier policy for the endpoint.
    pub fn hold_inbound(&self, at: EndpointId, policy: HoldPolicy) {
        assert!(policy.every_nth > 0 && policy.release_after > 0, "hold policy must be positive");
        self.inner.holding.lock().expect("fault controller poisoned").insert(at, policy);
    }

    /// Lifts the hold policy at `at`; whatever is still held is delivered.
    pub fn stop_holding(&self, at: EndpointId) {
        self.inner.holding.lock().expect("fault controller poisoned").remove(&at);
    }

    /// Datagrams discarded on the directed link `from -> to`.
    pub fn dropped_on(&self, from: EndpointId, to: EndpointId) -> u64 {
        self.inner
            .dropped_on
            .lock()
            .expect("fault controller poisoned")
            .get(&(from, to))
            .copied()
            .unwrap_or(0)
    }

    /// Datagrams sent twice on the directed link `from -> to`.
    pub fn duplicated_on(&self, from: EndpointId, to: EndpointId) -> u64 {
        self.inner
            .duplicated_on
            .lock()
            .expect("fault controller poisoned")
            .get(&(from, to))
            .copied()
            .unwrap_or(0)
    }

    /// Datagrams delivered out of order at `at`.
    pub fn reordered_at(&self, at: EndpointId) -> u64 {
        self.inner
            .reordered_at
            .lock()
            .expect("fault controller poisoned")
            .get(&at)
            .copied()
            .unwrap_or(0)
    }

    /// How many datagrams were sent twice.
    pub fn duplicated_datagrams(&self) -> u64 {
        self.inner.duplicated.load(Ordering::Relaxed)
    }

    /// How many datagrams were delivered after a later one overtook them.
    pub fn reordered_datagrams(&self) -> u64 {
        self.inner.reordered.load(Ordering::Relaxed)
    }

    fn duplicate_between(&self, from: EndpointId, to: EndpointId) -> bool {
        let mut links = self.inner.duplicating.lock().expect("fault controller poisoned");
        let Some(link) = links.get_mut(&(from, to)) else { return false };
        let index = link.seen;
        link.seen += 1;
        index.wrapping_add(link.seed).is_multiple_of(link.every_nth)
    }

    fn hold_policy(&self, at: EndpointId) -> Option<HoldPolicy> {
        self.inner.holding.lock().expect("fault controller poisoned").get(&at).copied()
    }

    /// Restores the link between `a` and `b`.
    ///
    /// Nothing is delivered as a result. Whatever the partition discarded
    /// stays discarded; recovery is QUIC's job from here, exactly as it is
    /// on a real network.
    pub fn heal(&self, a: EndpointId, b: EndpointId) {
        let mut cut = self.inner.cut.lock().expect("fault controller poisoned");
        cut.remove(&(a, b));
        cut.remove(&(b, a));
    }

    /// Whether the link is cut in both directions.
    pub fn is_partitioned(&self, a: EndpointId, b: EndpointId) -> bool {
        let cut = self.inner.cut.lock().expect("fault controller poisoned");
        cut.contains(&(a, b)) && cut.contains(&(b, a))
    }

    /// How many datagrams cut links have discarded so far.
    pub fn dropped_datagrams(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// Whether a datagram from `from` to `to` is discarded, recording it if
    /// so.
    ///
    /// The whole of the send path's decision, named so it can be exercised
    /// without a `Transmit` -- which cannot be constructed outside iroh (its
    /// `ecn` field is `pub(crate)` and it has no public constructor), so
    /// `poll_send` itself is not reachable from a unit test.
    fn discard_between(&self, from: EndpointId, to: EndpointId) -> bool {
        if !self.is_cut(from, to) {
            return false;
        }
        self.inner.dropped.fetch_add(1, Ordering::Relaxed);
        *self
            .inner
            .dropped_on
            .lock()
            .expect("fault controller poisoned")
            .entry((from, to))
            .or_insert(0) += 1;
        true
    }

    /// Wraps `network`'s transport for `local` so its datagrams pass through
    /// this controller.
    pub fn transport_for(
        &self,
        network: &TestNetwork,
        local: EndpointId,
    ) -> io::Result<Arc<FaultInjectingTransport>> {
        Ok(Arc::new(FaultInjectingTransport {
            inner: network.create_transport(local)?,
            local,
            controller: self.clone(),
        }))
    }
}

/// The address `endpoint` is reachable at on a [`TestNetwork`], in the same
/// encoding upstream uses.
fn peer_of(addr: &CustomAddr) -> Option<EndpointId> {
    if addr.id() != TEST_TRANSPORT_ID {
        return None;
    }
    let bytes: &[u8; 32] = addr.data().try_into().ok()?;
    EndpointId::from_bytes(bytes).ok()
}

/// Upstream's transport with a fault check in front of its sender.
#[derive(Debug)]
pub struct FaultInjectingTransport {
    inner: Arc<TestTransport>,
    local: EndpointId,
    controller: SimFaultController,
}

impl CustomTransport for FaultInjectingTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        Ok(Box::new(FaultInjectingEndpoint {
            inner: self.inner.bind()?,
            local: self.local,
            controller: self.controller.clone(),
            shaper: Shaper::default(),
            ready: VecDeque::new(),
        }))
    }
}

/// One received datagram, copied out of the caller's buffers so it can be
/// delivered later or in another order.
type Datagram = (Vec<u8>, noq_udp::RecvMeta, RecvInfo);

#[derive(Debug)]
struct FaultInjectingEndpoint {
    inner: Box<dyn CustomEndpoint>,
    local: EndpointId,
    controller: SimFaultController,
    shaper: Shaper<Datagram>,
    /// Datagrams cleared for delivery that did not fit the last buffers.
    ready: VecDeque<Datagram>,
}

impl FaultInjectingEndpoint {
    /// Releases everything held (an idle wire, or a lifted policy) and counts
    /// the datagrams that had been overtaken.
    fn release_held(&mut self) {
        let (released, overtaken) = self.shaper.drain();
        self.count_overtaken(overtaken);
        self.ready.extend(released);
    }

    fn count_overtaken(&self, overtaken: u64) {
        if overtaken == 0 {
            return;
        }
        self.controller.inner.reordered.fetch_add(overtaken, Ordering::Relaxed);
        *self
            .controller
            .inner
            .reordered_at
            .lock()
            .expect("fault controller poisoned")
            .entry(self.local)
            .or_insert(0) += overtaken;
    }

    /// Moves cleared datagrams into the caller's buffers, in order.
    fn fill(
        &mut self,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> usize {
        let mut count = 0;
        while count < bufs.len() {
            let Some((bytes, meta, info)) = self.ready.pop_front() else { break };
            if bufs[count].len() < bytes.len() {
                continue; // cannot happen with equal-sized buffers; never overrun one
            }
            bufs[count][..bytes.len()].copy_from_slice(&bytes);
            metas[count] = meta;
            recv_infos[count] = info;
            count += 1;
        }
        count
    }
}

impl CustomEndpoint for FaultInjectingEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.inner.watch_local_addrs()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(FaultInjectingSender {
            inner: self.inner.create_sender(),
            local: self.local,
            controller: self.controller.clone(),
        })
    }

    /// Cuts are not applied here: both endpoints on a cut link discard
    /// their own outbound datagrams, so nothing that should have been
    /// stopped ever reaches a receiver. What this does is the hold policy
    /// (reordering and delay), and with no policy it is a pass-through.
    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        let Some(policy) = self.controller.hold_policy(self.local) else {
            // No policy, or it was lifted: whatever is still held goes out
            // first, then the wire is passed through untouched.
            self.release_held();
            if self.ready.is_empty() {
                return self.inner.poll_recv(cx, bufs, metas, recv_infos);
            }
            return Poll::Ready(Ok(self.fill(bufs, metas, recv_infos)));
        };
        while self.ready.is_empty() {
            match self.inner.poll_recv(cx, bufs, metas, recv_infos) {
                Poll::Pending => {
                    // An idle wire releases what is held: delayed, not lost.
                    if self.shaper.is_empty() {
                        return Poll::Pending;
                    }
                    self.release_held();
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                Poll::Ready(Ok(arrived)) => {
                    let arrivals: Vec<Datagram> = (0..arrived)
                        .map(|i| {
                            (bufs[i][..metas[i].len].to_vec(), metas[i], recv_infos[i].clone())
                        })
                        .collect();
                    let (out, overtaken) = self.shaper.shape(policy, arrivals);
                    self.count_overtaken(overtaken);
                    // Everything that arrived may have been held. Poll again
                    // rather than call the wire idle: only `Pending` is idle.
                    self.ready.extend(out);
                }
            }
        }
        Poll::Ready(Ok(self.fill(bufs, metas, recv_infos)))
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.inner.max_transmit_segments()
    }
}

#[derive(Debug)]
struct FaultInjectingSender {
    inner: Arc<dyn CustomSender>,
    local: EndpointId,
    controller: SimFaultController,
}

impl CustomSender for FaultInjectingSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        self.inner.is_valid_send_addr(addr)
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        dst: &CustomAddr,
        src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(peer) = peer_of(dst) {
            if self.controller.discard_between(self.local, peer) {
                // `Ok`, not an error: a partitioned sender is not told its
                // packet went nowhere, any more than a real one is. Reporting
                // an error here would hand iroh a signal a real partition
                // never gives it, and the connection would fail in a way no
                // production network produces.
                return Poll::Ready(Ok(()));
            }
            let sent = self.inner.poll_send(cx, dst, src, transmit);
            if matches!(sent, Poll::Ready(Ok(())))
                && self.controller.duplicate_between(self.local, peer)
            {
                // The copy is best effort: if the carrier is not ready for a
                // second datagram, the original still went out once.
                if matches!(self.inner.poll_send(cx, dst, src, transmit), Poll::Ready(Ok(()))) {
                    self.controller.inner.duplicated.fetch_add(1, Ordering::Relaxed);
                    *self
                        .controller
                        .inner
                        .duplicated_on
                        .lock()
                        .expect("fault controller poisoned")
                        .entry((self.local, peer))
                        .or_insert(0) += 1;
                }
            }
            return sent;
        }
        self.inner.poll_send(cx, dst, src, transmit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// The carrier's no-hold-queue property, isolated from QUIC.
    ///
    /// This is the claim an end-to-end test cannot make. Datagrams a
    /// partition eats are still held by QUIC's own loss recovery and
    /// retransmitted after heal, which is production behaviour and wanted --
    /// so watching bytes arrive after a heal says nothing about whether the
    /// *carrier* queued them. Here there is no QUIC at all, and the question
    /// is answerable directly: healing releases nothing, because there is
    /// nothing to release.
    ///
    /// What it cannot reach, and why: proving the wrapper never forwards to
    /// its inner sender while cut would mean calling `poll_send` with a
    /// `Transmit`, and `Transmit`'s `ecn` field is `pub(crate)` with no
    /// public constructor, so one cannot be built outside iroh. The decision
    /// that gates forwarding is tested instead, which is the same branch
    /// `poll_send` takes.
    #[test]
    fn healing_releases_nothing_because_nothing_is_held() {
        let controller = SimFaultController::new();
        let (a, b) = (endpoint(1), endpoint(2));

        controller.partition(a, b);
        // Three datagrams offered to a cut link, each discarded on the spot.
        for _ in 0..3 {
            assert!(controller.discard_between(a, b), "a cut link must discard");
        }
        assert_eq!(controller.dropped_datagrams(), 3);

        controller.heal(a, b);
        assert_eq!(
            controller.dropped_datagrams(),
            3,
            "healing changed the discard count, so something was being held back and has \
             now been released -- a cut link must discard, not queue"
        );
        assert!(!controller.discard_between(a, b), "a healed link must carry");
        assert_eq!(controller.dropped_datagrams(), 3, "a healed link discarded a datagram");
    }

    /// A partition is a property of the link, not of the direction it was
    /// declared in. A carrier that filtered only one way would let a peer
    /// answer a request it should never have received.
    #[test]
    fn a_partition_is_symmetric() {
        let controller = SimFaultController::new();
        let (a, b) = (endpoint(1), endpoint(2));

        controller.partition(a, b);
        assert!(controller.is_partitioned(a, b));
        assert!(controller.is_partitioned(b, a), "the reverse direction is not cut");

        // Healing from the other side heals the same link.
        controller.heal(b, a);
        assert!(!controller.is_partitioned(a, b), "healing was direction-dependent");
    }

    /// Only the named link is cut. A controller that cut everything would
    /// make every partition test pass for the wrong reason.
    #[test]
    fn an_unrelated_link_is_untouched() {
        let controller = SimFaultController::new();
        let (a, b, c) = (endpoint(1), endpoint(2), endpoint(3));

        controller.partition(a, b);
        assert!(!controller.is_partitioned(a, c), "a link nobody cut is cut");
        assert!(!controller.discard_between(a, c), "a link nobody cut discarded a datagram");
        assert_eq!(controller.dropped_datagrams(), 0);
    }

    /// Firing the same fault twice is a schedule, not a bug.
    #[test]
    fn partition_and_heal_are_idempotent() {
        let controller = SimFaultController::new();
        let (a, b) = (endpoint(1), endpoint(2));

        controller.partition(a, b);
        controller.partition(a, b);
        assert!(controller.is_partitioned(a, b));
        controller.heal(a, b);
        controller.heal(a, b);
        assert!(!controller.is_partitioned(a, b));
    }

    /// A one-way cut stops one direction only, and the counters and the
    /// reverse direction show it.
    #[test]
    fn a_one_way_cut_stops_one_direction() {
        let controller = SimFaultController::new();
        let (a, b) = (endpoint(1), endpoint(2));

        controller.partition_one_way(a, b);
        assert!(controller.discard_between(a, b), "the cut direction must discard");
        assert!(!controller.discard_between(b, a), "the reverse direction must carry");
        assert!(controller.is_cut(a, b) && !controller.is_cut(b, a));
        assert!(!controller.is_partitioned(a, b), "a one-way cut is not a full partition");
        assert_eq!(controller.dropped_datagrams(), 1);

        controller.partition_one_way(b, a);
        assert!(controller.is_partitioned(a, b), "both directions cut is a partition");

        controller.heal_one_way(a, b);
        assert!(!controller.is_cut(a, b) && controller.is_cut(b, a));
    }

    /// Every nth datagram is duplicated, the phase is the seed, and the same
    /// parameters give the same decisions.
    #[test]
    fn duplication_is_periodic_and_seeded() {
        let decisions = |seed| {
            let controller = SimFaultController::new();
            let (a, b) = (endpoint(1), endpoint(2));
            controller.duplicate_datagrams(a, b, 3, seed);
            (0..9).map(|_| controller.duplicate_between(a, b)).collect::<Vec<_>>()
        };
        assert_eq!(decisions(0).iter().filter(|d| **d).count(), 3);
        assert_eq!(decisions(0), decisions(0));
        assert_ne!(decisions(0), decisions(1), "the seed must move the phase");
        let controller = SimFaultController::new();
        assert!(!controller.duplicate_between(endpoint(1), endpoint(2)), "off by default");
        assert!(!controller.duplicate_between(endpoint(2), endpoint(1)));
    }

    fn policy(every_nth: u64, release_after: u32) -> HoldPolicy {
        HoldPolicy { every_nth, release_after, seed: 0 }
    }

    /// Hold every datagram selected, release after one later datagram:
    /// adjacent datagrams swap.
    #[test]
    fn holding_with_release_after_one_swaps_neighbours() {
        let mut shaper = Shaper::default();
        let (out, overtaken) = shaper.shape(policy(2, 1), vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(out, vec![1, 0, 3, 2, 5, 4]);
        assert_eq!(overtaken, 3);
        assert!(shaper.is_empty());
    }

    /// A longer hold is a delay behind several datagrams, and what is still
    /// held when the wire goes idle is released, never lost.
    #[test]
    fn a_longer_hold_delays_and_an_idle_wire_releases() {
        let mut shaper = Shaper::default();
        let (out, overtaken) = shaper.shape(policy(5, 3), vec![0, 1, 2, 3, 4]);
        assert_eq!(out, vec![1, 2, 3, 0, 4]);
        assert_eq!(overtaken, 1);
        let (out, _) = shaper.shape(policy(5, 3), vec![5]);
        assert!(out.is_empty(), "datagram 5 is selected too, and is held");
        assert_eq!(shaper.drain().0, vec![5]);
        let mut shaper = Shaper::default();
        let (out, _) = shaper.shape(policy(1, 9), vec![7, 8]);
        assert!(out.is_empty());
        assert_eq!(shaper.drain().0, vec![7, 8], "an idle wire must release, in arrival order");
    }

    /// A held datagram that nothing overtook was delayed, not reordered, and
    /// must not be counted as evidence of reordering.
    #[test]
    fn holding_everything_preserves_order_and_counts_no_reordering() {
        let mut shaper = Shaper::default();
        let (out, overtaken) = shaper.shape(policy(1, 1), vec![0, 1, 2]);
        out.iter().zip(0..).for_each(|(got, want)| assert_eq!(*got, want));
        assert_eq!(overtaken, 0);
    }

    /// A datagram overtaken before the wire went idle is reordered evidence
    /// even though it is released by the drain rather than by its count.
    #[test]
    fn a_drain_reports_the_datagrams_that_were_overtaken() {
        let mut shaper = Shaper::default();
        let (out, overtaken) = shaper.shape(policy(2, 3), vec![0, 1]);
        assert_eq!((out, overtaken), (vec![1], 0));
        let (released, overtaken) = shaper.drain();
        assert_eq!((released, overtaken), (vec![0], 1));
    }

    /// No datagram is ever created or lost by shaping alone.
    #[test]
    fn shaping_conserves_datagrams() {
        for (n, k) in [(1, 1), (2, 1), (3, 2), (4, 5), (7, 1)] {
            let mut shaper = Shaper::default();
            let (mut out, _) = shaper.shape(policy(n, k), (0..50).collect());
            out.extend(shaper.drain().0);
            out.sort();
            assert_eq!(out, (0..50).collect::<Vec<_>>(), "every {n}th held for {k}");
        }
    }
}
