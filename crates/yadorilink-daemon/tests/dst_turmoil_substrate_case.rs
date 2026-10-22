//! A `Case`'s fault schedule, driven on its own clock, stopping and
//! restoring real substrate traffic.
//!
//! This is the join every previous piece was built toward, and each of those
//! pieces was landed alone so that a failure here has somewhere to point:
//!
//! ```text
//! Case::fault_schedule   (nanosecond offsets)
//!   ↓  run_schedule       -- when each fault fires
//!   ↓  CarrierFaults      -- which endpoints a device index means
//!   ↓  SimFaultController -- which links are cut
//!   ↓  FaultInjectingTransport
//!   ↓  real iroh QUIC over a real block lane
//! ```
//!
//! # What Turmoil is doing here, and what it is not
//!
//! Turmoil supplies the host scheduler, the virtual clock and the host
//! lifecycle. Device A and device B are separate hosts, so their futures are
//! stepped independently and a seed decides the order.
//!
//! It is **not** carrying the substrate's datagrams. Those ride iroh's custom
//! transport into `TestNetwork`, which is a different simulated network with
//! its own faults, owned by `SimFaultController`. Putting two devices on two
//! Turmoil hosts therefore does not mean their blocks crossed Turmoil's
//! network, and nothing here claims it does. When the control plane arrives
//! it will ride Turmoil's sockets, and a partition will have to cut both
//! planes to be a device partition at all.

#![cfg(turmoil)]

mod dst_support;

use std::sync::Arc;
use std::time::Duration;

use iroh::test_utils::test_transport::TestNetwork;
use yadorilink_daemon::test_support::sim_control_plane::ControlPlane;
use yadorilink_lane_ports::block_lane::LaneBlockStream;
use yadorilink_lane_ports::sim_fault::SimFaultController;
use yadorilink_lane_ports::testing::{TestAddressBook, TestPeerNode};
use yadorilink_peer_session::ports::{BlockStreamTransport, PeerBlockStream};
use yadorilink_sync_substrate::Lane;

use dst_support::case_ir::{Fault, NetFault, SimNanos};
use dst_support::device_network::{ControlPlaneHosts, DeviceNetworkFaults};
use dst_support::fault_carrier::CarrierFaults;
use dst_support::fault_schedule::{run_schedule_from, Activation, FaultClass, ScheduledInjectors};

const GROUP: &str = "scheduled-fault-group";

/// A whole phase's worth of round trips, so "it worked" and "it did not" are
/// each observed several times rather than once.
const ATTEMPTS_PER_PHASE: usize = 3;

/// Long enough that a healthy round trip never hits it. Simulated time, so
/// generous costs nothing.
const HEALTHY_BUDGET: Duration = Duration::from_millis(800);

/// Only ever evaluated while the link is cut.
const CUT_BUDGET: Duration = Duration::from_millis(500);

/// The control plane gets its own, much larger budgets.
///
/// A control attempt dials a fresh QUIC connection, and while there is no
/// established connection the clock is Turmoil's -- so a budget measured in
/// simulated seconds elapses in very few real steps, and can expire before
/// the peer host has been scheduled enough times to finish a handshake. An
/// 800ms budget failed on exactly one host ordering out of eight, which is
/// what that looks like from the outside. These are caps, not waits: a
/// healthy attempt returns in a fraction of them.
const CONTROL_HEALTHY_BUDGET: Duration = Duration::from_secs(10);

/// Only ever evaluated while the link is cut, where nothing can connect and
/// the whole budget is spent -- cheaply, because a disconnected host keeps
/// the clock virtual.
const CONTROL_CUT_BUDGET: Duration = Duration::from_secs(4);

/// The `Case`'s own schedule, in the nanoseconds `Case::fault_schedule`
/// carries: cut at 1s, heal at 20s.
///
/// The gap has to outlast the whole cut phase -- the settle sleep plus
/// `ATTEMPTS_PER_PHASE` attempts each running its budget out. An earlier
/// draft put the heal inside that window and the cut phase's last attempts
/// succeeded, correctly, against a link that really had healed.
///
/// Every number here is chosen against wall-clock cost, not simulated cost,
/// and the gap between the two is the point.
///
/// A partition does not close the connections it cuts -- deliberately, since
/// a real one does not either -- so an established QUIC connection survives
/// the whole cut phase, and while one exists turmoil's paused clock stops
/// auto-advancing (`turmoil_clock_limits.rs` bisects exactly where). The
/// heal offset is therefore paid in real seconds. At 60s it was 8 minutes
/// for eight seeds; at 15s it is under a minute for four, with the cut phase
/// finishing around 9s and the rest margin.
const PARTITION_AT_NANOS: u64 = 1_000_000_000;
const HEAL_AT_NANOS: u64 = 15_000_000_000;

/// Long enough to be past `PARTITION_AT_NANOS` however the healthy phase is
/// scheduled, and short enough to leave the cut phase room before the heal.
const SETTLE_AFTER_CUT: Duration = Duration::from_secs(2);

/// Deterministic per seed, and fixed before any host starts.
///
/// A fault schedule names devices by index; the carrier names them by
/// `EndpointId`. The mapping between the two has to exist before the hosts
/// do, or a fault at offset zero would have nothing to act on.
fn identity(seed: u64, which: u8) -> iroh::SecretKey {
    let mut bytes = [0u8; 32];
    bytes[0] = which;
    bytes[1..9].copy_from_slice(&seed.to_le_bytes());
    // Any 32 bytes are a valid Ed25519 secret key.
    iroh::SecretKey::from_bytes(&bytes)
}

/// Both hosts bind this. The peer's address has to be agreed before either
/// side runs, and an ephemeral port could not be.
const CONTROL_PORT: u16 = 9000;

fn payload() -> Vec<u8> {
    (0..4096u32).map(|i| (i % 251) as u8).collect()
}

/// Serves block lanes until the simulation ends.
///
/// It loops rather than serving one lane because a cut link leaves lanes
/// behind: a request opened while the link was down still reaches the accept
/// queue -- the stream is created before the datagrams carrying its contents
/// are discarded -- and never carries a request. A real peer's accept loop
/// has the same shape.
async fn serve_blocks(node: Arc<TestPeerNode>, body: Vec<u8>) {
    loop {
        let Some((_group, stream)) = node.accept_unclaimed_lane().await else { return };
        if stream.lane() != Lane::Block {
            continue;
        }
        let mut lane = LaneBlockStream::new(stream);
        let Ok(_request) = lane.recv_message(1024).await else { continue };
        if lane.send_message(b"found").await.is_err() {
            continue;
        }
        let _ = lane.send_body(&body).await;
    }
}

/// One block round trip, or `false` if it did not complete within `budget`.
async fn round_trip(from: &Arc<TestPeerNode>, to: &str, expected: &[u8], budget: Duration) -> bool {
    let transports = from.transports_for(to);
    let attempt = async {
        let mut lane = BlockStreamTransport::open(transports.as_ref(), GROUP).await.ok()?;
        lane.send_message(b"want").await.ok()?;
        lane.finish_send();
        if lane.recv_message(1024).await.ok()? != b"found" {
            return None;
        }
        lane.recv_body(expected.len()).await.ok()
    };
    matches!(tokio::time::timeout(budget, attempt).await, Ok(Some(bytes)) if bytes == expected)
}

async fn successes(from: &Arc<TestPeerNode>, to: &str, expected: &[u8], budget: Duration) -> usize {
    let mut ok = 0;
    for _ in 0..ATTEMPTS_PER_PHASE {
        if round_trip(from, to, expected, budget).await {
            ok += 1;
        }
    }
    ok
}

/// Waits until the peer is reachable on *every* plane.
///
/// Both, because a device is not reachable until all of its networks are and
/// the two come up independently. An earlier version waited only for the
/// substrate address book, and under some host orderings device A dialled a
/// control endpoint that had not bound yet -- so the scenario's healthy
/// phase failed before any fault had been injected, on some seeds and not
/// others. That is a readiness bug wearing the costume of a network one.
///
/// The fault epoch is taken after this on purpose. Measuring a `Case`'s
/// offsets from "the scenario started" would fold endpoint startup into the
/// `Case`'s own timing, differently on every run and every host ordering.
async fn wait_until_ready(
    book: &TestAddressBook,
    device_id: &str,
    control_ready: &std::sync::atomic::AtomicBool,
) {
    for _ in 0..4_000 {
        if book.address_of(device_id).is_some()
            && control_ready.load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("{device_id} never became reachable on both planes");
}

/// One simulation: two hosts, one `Case` schedule, three phases.
fn run_one(seed: u64) -> turmoil::Result {
    let mut sim = turmoil::Builder::new()
        .rng_seed(seed)
        // Distinct seeds must reach distinct host orderings, or running
        // several of them proves nothing beyond running one several times.
        .enable_random_order()
        // iroh's endpoint watches network interfaces through netlink, which
        // is a real socket and panics outright on a runtime with the I/O
        // driver off. The substrate's own datagrams do not need it -- they
        // go through the custom transport -- but the endpoint will not start
        // without it.
        .enable_tokio_io()
        // One tick per millisecond is turmoil's default, and a schedule
        // measured in seconds is tens of thousands of steps. Each step polls
        // two iroh endpoints, so the step count is what this run costs.
        .tick_duration(Duration::from_millis(10))
        .simulation_duration(Duration::from_secs(300))
        .build();

    // Everything shared between the hosts is built before either starts, so
    // the index-to-endpoint mapping is fixed up front.
    let network = TestNetwork::new();
    let controller = SimFaultController::new();
    let book = TestAddressBook::new();
    let a_key = identity(seed, 1);
    let b_key = identity(seed, 2);
    let (a_id, b_id) = (a_key.public(), b_key.public());
    let body = payload();

    // Device B: comes up, publishes, and serves block lanes for the run.

    // Set by device B once its control endpoint is bound and accepting.
    // The address book covers the substrate; nothing covered this.
    let control_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let b_ready = control_ready.clone();

    let b_state = std::sync::Mutex::new(Some((b_key, body.clone())));
    let b_network = network.clone();
    let b_controller = controller.clone();
    let b_book = book.clone();
    sim.host("device-b", move || {
        // `host` takes an `Fn` because turmoil may restart a host. This one
        // is never restarted, and a second start would need a second
        // identity anyway -- taking it is the honest encoding of "starts
        // once", and panics rather than silently running under a different
        // identity than the carrier's mapping names.
        let taken = b_state.lock().expect("device-b identity lock").take();
        let network = b_network.clone();
        let controller = b_controller.clone();
        let book = b_book.clone();
        let ready = b_ready.clone();
        async move {
            let (key, body) = taken.expect("device-b starts exactly once");
            let node = TestPeerNode::start_simulated_with_identity(
                "device-b",
                book,
                &network,
                &controller,
                key,
            )
            .await;
            // Both planes, on one host: the substrate endpoint above and the
            // control endpoint below are how this device is reachable, and a
            // partition has to stop both.
            let endpoint = ControlPlane::bind(CONTROL_PORT).await;
            endpoint.answer_probes();
            ready.store(true, std::sync::atomic::Ordering::Release);
            serve_blocks(node, body).await;
            Ok(())
        }
    });

    // Device A: the scenario.
    let a_network = network.clone();
    let a_controller = controller.clone();
    let a_book = book.clone();
    sim.client("device-a", async move {
        let a = TestPeerNode::start_simulated_with_identity(
            "device-a",
            a_book.clone(),
            &a_network,
            &a_controller,
            a_key,
        )
        .await;
        wait_until_ready(&a_book, "device-b", &control_ready).await;

        let control = ControlPlane::bind(CONTROL_PORT).await;
        let b_control_addr = std::net::SocketAddr::new(turmoil::lookup("device-b"), CONTROL_PORT);

        // One owner, both planes. The substrate knows devices by
        // `EndpointId`, the control plane by Turmoil host name, and the
        // `Case`'s index is what joins them.
        let schedule = vec![
            (
                SimNanos::from_nanos(PARTITION_AT_NANOS),
                Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }),
            ),
            (
                SimNanos::from_nanos(HEAL_AT_NANOS),
                Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 }),
            ),
        ];
        // Specified up front, so a partition that never reaches the carrier
        // fails the gate at the end instead of reading as a green run.
        let injectors = ScheduledInjectors::for_spec(&schedule)
            .expect("the Case names a fault this scheduler cannot inject")
            .with_carrier(DeviceNetworkFaults::with_control_plane(
                CarrierFaults::new(a_controller.clone(), vec![a_id, b_id]),
                ControlPlaneHosts::new(vec!["device-a".to_string(), "device-b".to_string()]),
            ));

        // Phase 1: both planes carry before the schedule cuts anything.
        let before = successes(&a, "device-b", &body, HEALTHY_BUDGET).await;
        assert_eq!(
            before, ATTEMPTS_PER_PHASE,
            "seed {seed}: substrate traffic was already failing before the Case cut anything, \
             so nothing below is attributable to the schedule"
        );
        assert!(
            control.can_reach(b_control_addr, CONTROL_HEALTHY_BUDGET).await,
            "seed {seed}: the control plane was already failing before the Case cut anything"
        );

        // Both planes are up and carrying. From here the `Case`'s offsets
        // measure what the `Case` meant them to.
        //
        // After the healthy phase, not before it: phase 1 spends up to
        // `ATTEMPTS_PER_PHASE * HEALTHY_BUDGET` of simulated time, which is
        // longer than `PARTITION_AT_NANOS`, so an epoch taken above lets the
        // cut land in the middle of the phase that is supposed to establish a
        // healthy baseline. `run_schedule_from`'s own doc comment has the
        // worked example from the stack scenario, where the same mistake
        // produced a silent pass rather than a loud failure.
        let fault_epoch = tokio::time::Instant::now();
        let scheduler = {
            let injectors = injectors.clone();
            tokio::spawn(async move { run_schedule_from(fault_epoch, schedule, injectors).await })
        };
        assert!(
            !a_controller.is_partitioned(a_id, b_id),
            "seed {seed}: the link was cut before its scheduled offset"
        );

        // Phase 2: the scheduled cut stops them.
        tokio::time::sleep(SETTLE_AFTER_CUT).await;
        assert!(
            a_controller.is_partitioned(a_id, b_id),
            "seed {seed}: the Case's partition never reached the carrier"
        );
        let dropped_before = a_controller.dropped_datagrams();
        let during = successes(&a, "device-b", &body, CUT_BUDGET).await;
        assert_eq!(during, 0, "seed {seed}: block traffic crossed a link the Case had cut");
        // The plane that makes this a device partition rather than a
        // substrate one. Cutting only the substrate would leave the devices
        // talking, and a scenario asserting on blocks alone would not notice.
        assert!(
            !control.can_reach(b_control_addr, CONTROL_CUT_BUDGET).await,
            "seed {seed}: control traffic crossed a link the Case had cut, so these devices \
             were not partitioned -- only their substrate was"
        );
        assert!(
            a_controller.dropped_datagrams() > dropped_before,
            "seed {seed}: the link is cut but nothing was discarded, so the attempts never \
             reached the carrier"
        );
        // The cut discarded real datagrams: the partition was injected, not
        // merely enabled, and the zero-successes above is the observed effect.
        injectors.credit_carrier_partition(dropped_before, a_controller.dropped_datagrams());
        injectors.record_observed(FaultClass::NetPartition);
        assert!(
            a_controller.is_partitioned(a_id, b_id),
            "seed {seed}: the heal fired while the cut phase was still running, so the zero \
             above may just be attempts that ran out of budget"
        );

        // Phase 3: the scheduled heal brings them back, on the same hosts,
        // the same endpoints and the same network.
        scheduler
            .await
            .expect("the scheduler task")
            .expect("the schedule must not name a device this run does not have");
        assert!(
            !a_controller.is_partitioned(a_id, b_id),
            "seed {seed}: the Case's heal never reached the carrier"
        );
        let after = successes(&a, "device-b", &body, HEALTHY_BUDGET).await;
        assert_eq!(
            after, ATTEMPTS_PER_PHASE,
            "seed {seed}: substrate traffic did not recover after heal"
        );
        assert!(
            control.can_reach(b_control_addr, CONTROL_HEALTHY_BUDGET).await,
            "seed {seed}: the control plane did not recover after heal"
        );

        // The carrier handled both network faults, and the plan handled
        // neither -- one owner per variant.
        let trace = injectors.trace();
        assert!(
            matches!(
                trace.as_slice(),
                [
                    Activation::Carried { outcome: cut, .. },
                    Activation::Carried { outcome: healed, .. }
                ] if cut.fully_applied() && healed.fully_applied()
            ),
            "seed {seed}: the schedule's network faults did not all go to the carrier: {trace:?}"
        );
        assert!(
            injectors.net_plan().partition_windows.is_empty(),
            "seed {seed}: the fault plan opened a partition window too, so this link had two \
             owners"
        );
        // Every fault the Case named reached its target.
        injectors.assert_gate();
        // Both planes, every time. A trace where one plane reported
        // `Applied` and the other did not would be a half-applied partition
        // -- which the phases above would have caught, but only by failing
        // in a way that points at the product rather than the harness.
        for activation in &trace {
            if let Activation::Carried { outcome, at_nanos } = activation {
                assert!(
                    outcome.control.is_some(),
                    "seed {seed}: the fault at {at_nanos}ns reached no control plane, so this \
                     scenario cut only the substrate"
                );
                assert!(
                    outcome.fully_applied(),
                    "seed {seed}: the fault at {at_nanos}ns was applied to some planes and \
                     not others: {outcome:?}"
                );
            }
        }

        Ok(())
    });

    sim.run()
}

/// Several seeds, because `enable_random_order` gives each a different host
/// ordering, and a property that held under one ordering and not another
/// would be a property of the scheduler rather than of the system.
///
/// Four rather than sixteen, because each costs its schedule in real
/// seconds. When the clock limit lifts this grows by changing one number.
#[test]
fn a_cases_schedule_stops_and_restores_both_planes_across_two_hosts() {
    for seed in dst_support::seeds(4) {
        run_one(seed).unwrap_or_else(|e| panic!("seed {seed} failed: {e}"));
    }
}
