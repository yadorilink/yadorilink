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
//! # What a partition does not do
//!
//! It does not close connections, drop state, or tell iroh anything. Both
//! endpoints go on believing the peer is reachable and go on retransmitting
//! into the dark, which is what makes the healed case a real recovery rather
//! than a fresh connection.

#![cfg(feature = "test-support")]

use std::collections::HashSet;
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
    /// Normalised pairs, so `(a, b)` and `(b, a)` are the same cut link.
    cut: Mutex<HashSet<(EndpointId, EndpointId)>>,
    /// Every datagram a cut link has discarded, across all links.
    ///
    /// Evidence, not bookkeeping. A test that partitions two endpoints and
    /// then watches a request time out has not distinguished "the partition
    /// stopped it" from "nothing was ever sent"; this counter does.
    dropped: AtomicU64,
}

fn link(a: EndpointId, b: EndpointId) -> (EndpointId, EndpointId) {
    if a.as_bytes() <= b.as_bytes() {
        (a, b)
    } else {
        (b, a)
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
        self.inner.cut.lock().expect("fault controller poisoned").insert(link(a, b));
    }

    /// Restores the link between `a` and `b`.
    ///
    /// Nothing is delivered as a result. Whatever the partition discarded
    /// stays discarded; recovery is QUIC's job from here, exactly as it is
    /// on a real network.
    pub fn heal(&self, a: EndpointId, b: EndpointId) {
        self.inner.cut.lock().expect("fault controller poisoned").remove(&link(a, b));
    }

    pub fn is_partitioned(&self, a: EndpointId, b: EndpointId) -> bool {
        self.inner.cut.lock().expect("fault controller poisoned").contains(&link(a, b))
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
        if !self.is_partitioned(from, to) {
            return false;
        }
        self.inner.dropped.fetch_add(1, Ordering::Relaxed);
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
        }))
    }
}

#[derive(Debug)]
struct FaultInjectingEndpoint {
    inner: Box<dyn CustomEndpoint>,
    local: EndpointId,
    controller: SimFaultController,
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

    /// Receiving is not filtered, and does not need to be: both endpoints on
    /// a cut link discard their own outbound datagrams, so nothing that
    /// should have been stopped ever reaches a receiver to be stopped there.
    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, metas, recv_infos)
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
}
