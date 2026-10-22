//! The substrate-advertisement helper's own ordering contract.
//!
//! `support::advertise_substrate_over` has one job: deliver every device's
//! substrate address to every other device, whatever order their stacks
//! finish starting in. That contract is invisible to the fixtures that use
//! it, because a dropped direction does not fail where it happens -- it
//! fails much later as "nothing converged", and only sometimes, since which
//! direction is lost depends on which orchestrator runtime won a startup
//! race.
//!
//! Real daemons cannot express "B is still starting while A is already
//! serving" on purpose, so these tests drive the helper through
//! `SubstrateDevices` with a readiness order chosen here.
//!
//! Note what is deliberately NOT asserted: `AddressDirectory::resolve`. A
//! directory self-records in `publish` -- "so a loopback deployment where
//! every peer is this process resolves without a round trip through the
//! plane" -- so a resolve-based assertion passes even when no advertisement
//! happened at all, and proves nothing about this helper. What is observed
//! instead is the delivery itself: which address was recorded into which
//! device's directory.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use support::{SubstrateAddress, SubstrateDevices};
use yadorilink_sync_substrate::PeerId;

/// Devices whose stacks come up in a staggered order: device `i` only reports
/// an address on its `i + 1`-th poll, so at the moment device 0 is first seen
/// serving, every later device is still starting.
///
/// That is the exact state a single-pass distribution mishandles. It waits
/// for the SOURCE, then walks the targets and skips any that is not ready --
/// with no second pass, so the skipped direction is gone for the rest of the
/// test.
struct StaggeredDevices {
    polls: Vec<AtomicUsize>,
    /// `(target device, address delivered to it)`, in delivery order.
    delivered: Mutex<Vec<(usize, SubstrateAddress)>>,
}

impl StaggeredDevices {
    fn new(count: usize) -> Self {
        Self {
            polls: (0..count).map(|_| AtomicUsize::new(0)).collect(),
            delivered: Mutex::new(Vec::new()),
        }
    }

    /// The address device `index` serves on, as this fake mints it: distinct
    /// per device and derived from the index, so a misdelivered address is
    /// identifiable rather than merely absent.
    fn address_of(index: usize) -> SubstrateAddress {
        let mut key = [0u8; 32];
        key[0] = u8::try_from(index + 1).expect("these tests use a handful of devices");
        (
            PeerId::from_bytes(key),
            vec![format!("127.0.0.1:{}", 40000 + index).parse().expect("a literal socket address")],
            Vec::new(),
        )
    }

    fn delivered_to(&self, target: usize) -> Vec<PeerId> {
        self.delivered
            .lock()
            .expect("no test task panics while holding this")
            .iter()
            .filter(|(to, _)| *to == target)
            .map(|(_, (peer, _, _))| *peer)
            .collect()
    }
}

impl SubstrateDevices for StaggeredDevices {
    fn device_count(&self) -> usize {
        self.polls.len()
    }

    fn serving_address(&self, index: usize) -> Option<SubstrateAddress> {
        let seen = self.polls[index].fetch_add(1, Ordering::SeqCst);
        // Device 0 is serving immediately; device 1 needs one more poll,
        // device 2 two more, and so on.
        (seen >= index).then(|| Self::address_of(index))
    }

    fn record(&self, target: usize, address: &SubstrateAddress) {
        self.delivered
            .lock()
            .expect("no test task panics while holding this")
            .push((target, address.clone()));
    }

    fn describe(&self, index: usize) -> String {
        format!("staggered-device-{index}")
    }
}

/// Every ordered pair is delivered exactly once, even though each device
/// starts serving strictly after the one before it.
///
/// A single-pass distribution fails this deterministically: device 0 is
/// serving when it is that device's turn to distribute, while devices 1 and 2
/// are not yet, so 0 -> 1 and 0 -> 2 are skipped and never retried.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn every_direction_is_delivered_however_late_a_device_starts_serving() {
    let devices = StaggeredDevices::new(3);

    support::advertise_substrate_over(&devices).await;

    for target in 0..3 {
        let received = devices.delivered_to(target);
        let expected: Vec<PeerId> = (0..3)
            .filter(|source| *source != target)
            .map(|source| StaggeredDevices::address_of(source).0)
            .collect();

        assert_eq!(
            received, expected,
            "device {target} must be taught where every other device answers, and nothing else. \
             A missing entry is a direction this helper dropped because that device's stack had \
             not come up yet when the source distributed -- the failure mode the barrier exists \
             to remove, which in a real fixture surfaces only as a later non-convergence."
        );
    }
}

/// The barrier waits for a device rather than proceeding without it.
///
/// The complement of the test above: a device that never serves must fail the
/// helper loudly and by name, not be quietly left out of everyone's directory
/// while the fixture goes on to wait for a convergence that cannot happen.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_device_that_never_serves_fails_the_helper_by_name() {
    /// Device 1 never reports an address; device 0 always does.
    struct NeverServes;

    impl SubstrateDevices for NeverServes {
        fn device_count(&self) -> usize {
            2
        }

        fn serving_address(&self, index: usize) -> Option<SubstrateAddress> {
            (index == 0).then(|| StaggeredDevices::address_of(0))
        }

        fn record(&self, _target: usize, _address: &SubstrateAddress) {
            panic!("nothing may be distributed before every device is proven to be serving");
        }

        fn describe(&self, index: usize) -> String {
            format!("never-serving-device-{index}")
        }
    }

    // Caught through a task rather than `catch_unwind`, which cannot straddle
    // the helper's await points.
    let failure = tokio::spawn(async { support::advertise_substrate_over(&NeverServes).await })
        .await
        .expect_err("a device that never serves must fail the helper, not be skipped");

    let panic = failure.into_panic();
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or_default();
    assert!(
        message.contains("never-serving-device-1"),
        "the failure must name the device that never served, so a fixture hitting this knows \
         which stack to look at; got: {message}"
    );
}

/// An address published AFTER the barrier reaches every peer.
///
/// The barrier distributes what each device is serving on at the moment it
/// runs, and that is not final: iroh keeps learning about an endpoint after
/// it binds, and a restarted node's address changes again shortly afterwards.
/// A fixture that reads once leaves its peers holding an address nothing
/// answers on -- and because the substrate has no relay to fall back to and
/// its dial carries no deadline, the resulting dial does not fail, it simply
/// never returns.
///
/// Drives the shipped `republish_on_change` rather than restating what it
/// does, and asserts on the delivery itself. No wall-clock anywhere: the
/// publisher sends, the loop delivers, and the channel closing is what ends
/// it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_address_published_after_the_barrier_still_reaches_every_peer() {
    use yadorilink_sync_substrate::PeerAddress;

    let peer = StaggeredDevices::address_of(0).0;
    let barrier_captured: std::net::SocketAddr = "127.0.0.1:40000".parse().expect("literal");
    let republished: std::net::SocketAddr = "127.0.0.1:49999".parse().expect("literal");

    let (tx, rx) =
        tokio::sync::watch::channel(PeerAddress::new(peer).with_direct([barrier_captured]));

    // Two peers, each holding whatever it was last told.
    let held: Arc<Mutex<Vec<Option<Vec<std::net::SocketAddr>>>>> =
        Arc::new(Mutex::new(vec![None, None]));

    let sink = Arc::clone(&held);
    let pump = tokio::spawn(support::republish_on_change(rx, move |address| {
        let mut held = sink.lock().expect("no test task panics holding this");
        for slot in held.iter_mut() {
            *slot = Some(address.1.clone());
        }
    }));

    // Each send is observed before the next: a `watch` channel keeps only
    // the latest value, so two sends in a row can legitimately be seen as
    // one, and the loop would never see the address it is supposed to
    // deliver. Yielding is cooperative scheduling, not waiting -- there is
    // no clock here.
    let settle = || async {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    };

    // The real move...
    tx.send(PeerAddress::new(peer).with_direct([republished])).expect("the loop is alive");
    settle().await;
    // ...and then an address naming nowhere, which must NOT replace it.
    // Ordered this way on purpose: sent first, an empty update would be
    // overwritten by the real one and the guard would be untested.
    tx.send(PeerAddress::new(peer)).expect("the loop is alive");
    settle().await;
    drop(tx);
    pump.await.expect("the republish loop must end when the publisher goes away");

    let held = held.lock().expect("no test task panics holding this");
    for (index, slot) in held.iter().enumerate() {
        let addrs = slot.as_ref().unwrap_or_else(|| panic!("peer {index} was told nothing at all"));
        assert_eq!(
            addrs,
            &vec![republished],
            "peer {index} must end up holding the address the publisher moved to, and only that. \
             A peer left on the address the barrier captured dials a socket nothing answers on, \
             and that dial never returns rather than failing."
        );
    }
}
