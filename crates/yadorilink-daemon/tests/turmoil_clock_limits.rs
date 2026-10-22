//! Where Turmoil's virtual clock stops working for this project, found by
//! bisection and kept so the answer does not have to be found again.
//!
//! Turmoil pauses each host's tokio clock and advances it by sleeping a tick
//! at a time, relying on tokio's `start_paused` auto-advance -- which only
//! fires while the runtime is idle. Anything that keeps a host's runtime
//! perpetually runnable therefore turns every simulated sleep back into a
//! real one, silently: the scenario still passes, it just takes as long as
//! it claims to simulate.
//!
//! Each test below adds one thing to the one above it. The first four hold;
//! the fifth does not, and names the boundary:
//!
//! ```text
//! turmoil alone                          virtual
//! + enable_tokio_io()                    virtual
//! + one live iroh endpoint               virtual
//! + two hosts, both endpoints idle       virtual
//! + one QUIC block exchange between them REAL  (~20s for 20s)
//! ```
//!
//! So it is not the I/O driver, not iroh's presence, and not having two
//! hosts. It is an *established* QUIC connection. Until that is resolved, a
//! scenario with live peer traffic pays wall-clock time for its simulated
//! time, which is what makes long partition windows and multi-seed sweeps
//! expensive rather than free.

#![cfg(turmoil)]
use std::time::Duration;

/// Does turmoil's virtual clock work at all here, with nothing else running?
#[test]
fn a_bare_turmoil_sleep_is_virtual() {
    let started = std::time::Instant::now();
    let mut sim = turmoil::Builder::new().simulation_duration(Duration::from_secs(120)).build();
    sim.client("c", async {
        tokio::time::sleep(Duration::from_secs(20)).await;
        Ok(())
    });
    sim.run().expect("sim");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "bare sleep took {elapsed:?}");
}

/// And with the I/O driver enabled, which iroh requires?
#[test]
fn a_turmoil_sleep_with_io_enabled_is_virtual() {
    let started = std::time::Instant::now();
    let mut sim = turmoil::Builder::new()
        .enable_tokio_io()
        .simulation_duration(Duration::from_secs(120))
        .build();
    sim.client("c", async {
        tokio::time::sleep(Duration::from_secs(20)).await;
        Ok(())
    });
    sim.run().expect("sim");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "sleep with io took {elapsed:?}");
}

/// And with one iroh endpoint alive inside the host?
#[test]
fn a_turmoil_sleep_with_an_iroh_endpoint_alive() {
    use yadorilink_lane_ports::sim_fault::SimFaultController;
    use yadorilink_lane_ports::testing::{TestAddressBook, TestPeerNode};

    let started = std::time::Instant::now();
    let mut sim = turmoil::Builder::new()
        .enable_tokio_io()
        .simulation_duration(Duration::from_secs(120))
        .build();
    let network = iroh::test_utils::test_transport::TestNetwork::new();
    let controller = SimFaultController::new();
    let book = TestAddressBook::new();
    sim.client("c", async move {
        let _node = TestPeerNode::start_simulated_with_identity(
            "device-a",
            book,
            &network,
            &controller,
            iroh::SecretKey::from_bytes(&[9; 32]),
        )
        .await;
        tokio::time::sleep(Duration::from_secs(20)).await;
        Ok(())
    });
    sim.run().expect("sim");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "sleep with a live iroh endpoint took {elapsed:?}");
}

/// Two hosts, each with an endpoint, with no traffic between them.
#[test]
fn two_hosts_with_endpoints_and_no_traffic() {
    use yadorilink_lane_ports::sim_fault::SimFaultController;
    use yadorilink_lane_ports::testing::{TestAddressBook, TestPeerNode};

    let started = std::time::Instant::now();
    let mut sim = turmoil::Builder::new()
        .enable_tokio_io()
        .simulation_duration(Duration::from_secs(120))
        .build();
    let network = iroh::test_utils::test_transport::TestNetwork::new();
    let controller = SimFaultController::new();
    let book = TestAddressBook::new();

    let b_key = std::sync::Mutex::new(Some(iroh::SecretKey::from_bytes(&[8; 32])));
    let (bn, bc, bb) = (network.clone(), controller.clone(), book.clone());
    sim.host("device-b", move || {
        let key = b_key.lock().unwrap().take();
        let (n, c, bk) = (bn.clone(), bc.clone(), bb.clone());
        async move {
            let _node = TestPeerNode::start_simulated_with_identity(
                "device-b",
                bk,
                &n,
                &c,
                key.expect("once"),
            )
            .await;
            std::future::pending::<()>().await;
            Ok(())
        }
    });

    sim.client("device-a", async move {
        let _node = TestPeerNode::start_simulated_with_identity(
            "device-a",
            book,
            &network,
            &controller,
            iroh::SecretKey::from_bytes(&[9; 32]),
        )
        .await;
        tokio::time::sleep(Duration::from_secs(20)).await;
        Ok(())
    });
    sim.run().expect("sim");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "two idle hosts took {elapsed:?}");
}

/// Two hosts that have actually exchanged a block, then sleep.
///
/// The boundary. Ignored rather than deleted: it is the characterisation of
/// a limit this project has to work within or fix, and a deleted test
/// documents nothing. Run it with `--ignored` to check whether an iroh or
/// turmoil upgrade has moved the line.
#[test]
#[ignore = "documents a known limit: an established QUIC connection defeats turmoil's paused clock"]
fn two_hosts_after_one_block_exchange() {
    use yadorilink_lane_ports::block_lane::LaneBlockStream;
    use yadorilink_lane_ports::sim_fault::SimFaultController;
    use yadorilink_lane_ports::testing::{TestAddressBook, TestPeerNode};
    use yadorilink_peer_session::ports::{BlockStreamTransport, PeerBlockStream};

    let started = std::time::Instant::now();
    let mut sim = turmoil::Builder::new()
        .enable_tokio_io()
        .simulation_duration(Duration::from_secs(120))
        .build();
    let network = iroh::test_utils::test_transport::TestNetwork::new();
    let controller = SimFaultController::new();
    let book = TestAddressBook::new();

    let b_key = std::sync::Mutex::new(Some(iroh::SecretKey::from_bytes(&[8; 32])));
    let (bn, bc, bb) = (network.clone(), controller.clone(), book.clone());
    sim.host("device-b", move || {
        let key = b_key.lock().unwrap().take();
        let (n, c, bk) = (bn.clone(), bc.clone(), bb.clone());
        async move {
            let node = TestPeerNode::start_simulated_with_identity(
                "device-b",
                bk,
                &n,
                &c,
                key.expect("once"),
            )
            .await;
            loop {
                let Some((_g, stream)) = node.accept_unclaimed_lane().await else { return Ok(()) };
                let mut lane = LaneBlockStream::new(stream);
                let Ok(_r) = lane.recv_message(1024).await else { continue };
                let _ = lane.send_message(b"found").await;
                let _ = lane.send_body(b"hi").await;
            }
        }
    });

    sim.client("device-a", async move {
        let a = TestPeerNode::start_simulated_with_identity(
            "device-a",
            book.clone(),
            &network,
            &controller,
            iroh::SecretKey::from_bytes(&[9; 32]),
        )
        .await;
        while book.address_of("device-b").is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let t = a.transports_for("device-b");
        let mut lane = BlockStreamTransport::open(t.as_ref(), "g").await.expect("open");
        lane.send_message(b"want").await.expect("send");
        lane.finish_send();
        assert_eq!(lane.recv_message(1024).await.expect("hdr"), b"found");
        assert_eq!(lane.recv_body(2).await.expect("body"), b"hi");

        tokio::time::sleep(Duration::from_secs(20)).await;
        Ok(())
    });
    sim.run().expect("sim");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "after a block exchange, sleeping took {elapsed:?}");
}
