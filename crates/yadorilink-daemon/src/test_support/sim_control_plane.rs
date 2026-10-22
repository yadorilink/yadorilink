//! A second network between two simulated devices, so a scenario can ask
//! whether they can reach each other *at all*.
//!
//! Every scenario that partitions devices needs this, and the reason is that
//! "sync stopped" and "the devices are isolated" are different claims:
//!
//! * Cut the **substrate** and sync stops, because a Change travels the
//!   substrate's reconciliation lane. The devices are degraded, not
//!   partitioned -- anything else they are connected by still carries.
//! * Cut **every plane** and nothing reaches anything.
//!
//! A test that only checked that sync had stopped cannot tell those apart,
//! and would report an isolation the run never produced. What separates them
//! is a reachability probe on a network the substrate fault does not touch,
//! which is what this is.
//!
//! # Why a bare datagram echo
//!
//! The question is "can a packet get from this host to that one", and a
//! datagram answers it with nothing in between. This used to be asked over a
//! QUIC control channel from the legacy transport, which answered the same
//! question through a handshake, a connection and a stream -- every one of
//! which has failure modes of its own, so a false negative could mean the
//! partition worked or could mean the handshake did not finish in the budget.
//!
//! It also tied the reachability probe to a transport the cutover deletes.
//! When that transport goes, a mechanical fix-up would have removed the probe
//! and left the "sync stopped" half of each scenario -- which still passes,
//! and no longer distinguishes anything.
//!
//! # What makes this a different plane from the substrate
//!
//! These sockets are Turmoil's own, so they are cut by `turmoil::partition`
//! and by nothing else. The substrate rides iroh's custom carrier into a
//! `TestNetwork`, cut by `SimFaultController`. `DeviceNetworkFaults` is what
//! drives both from one `Case` fault so that a whole-device partition cannot
//! miss one of them; a substrate-only cut deliberately reaches only the
//! second.
//!
//! # Probes are one-directional
//!
//! One host dials and the rest answer. The question is whether two devices
//! are isolated from each other, and one direction answers it: on a cut link
//! the datagram does not arrive, and on a healthy one the reply comes back
//! over the same link. Giving every host a dialler would double the sockets
//! for a symmetry no scenario reads.

#![cfg(turmoil)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_transport::sim_net::UdpSocket;

/// What a probe sends, and what an answering host sends back unchanged.
///
/// Echoed rather than answered with a fixed token so a reply can be matched
/// to its probe: a stale datagram from an earlier attempt arriving late would
/// otherwise report a cut link as reachable.
const PROBE: &[u8] = b"reachable?";

/// How long to wait for one probe's reply before sending another.
///
/// Sent again rather than waited on: UDP has no retransmission, and a single
/// datagram lost for any reason would read as an isolated device. Turmoil's
/// network does not lose datagrams on an uncut link, so this is a guard
/// against the simulation's scheduling rather than against loss.
const PROBE_INTERVAL: Duration = Duration::from_millis(200);

/// The largest reply this will read. A probe is a few bytes; anything larger
/// arriving on this port is not a reply to it.
const REPLY_BUFFER: usize = 64;

/// One device's socket on the control plane.
pub struct ControlPlane {
    socket: Arc<UdpSocket>,
}

impl ControlPlane {
    /// Binds this host's control port.
    ///
    /// Unspecified rather than a literal address: Turmoil fills in the
    /// current host's, and an explicit loopback would opt the control plane
    /// out of the simulated network it is supposed to ride -- a probe that
    /// never left the host would report every partition as reachable.
    pub async fn bind(port: u16) -> Self {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let socket = UdpSocket::bind(bind).await.expect("bind this host's control port");
        Self { socket: Arc::new(socket) }
    }

    /// Answers probes until the simulation ends.
    ///
    /// Spawn this on a host that other hosts probe. It answers whoever asked,
    /// rather than a configured peer: the socket is reachable or it is not,
    /// and deciding who may ask would be an authorization question this plane
    /// does not have.
    pub fn answer_probes(&self) -> tokio::task::JoinHandle<()> {
        let socket = self.socket.clone();
        tokio::spawn(async move {
            let mut buffer = [0u8; REPLY_BUFFER];
            loop {
                let Ok((len, from)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                if socket.send_to(&buffer[..len], from).await.is_err() {
                    return;
                }
            }
        })
    }

    /// Whether `peer` answers within `budget`.
    ///
    /// Each attempt is a fresh datagram. A partition has to stop a device
    /// from reaching its peer, and anything that reused established state
    /// would only be asking whether that state still worked.
    ///
    /// `budget` is a cap and not a wait: a healthy link answers on the first
    /// probe, and the budget is only ever spent in full when the answer is
    /// "no".
    pub async fn can_reach(&self, peer: SocketAddr, budget: Duration) -> bool {
        let attempt = async {
            let mut buffer = [0u8; REPLY_BUFFER];
            loop {
                if self.socket.send_to(PROBE, peer).await.is_err() {
                    // A send that fails locally is not an answer about the
                    // peer, so try again rather than concluding anything.
                    tokio::time::sleep(PROBE_INTERVAL).await;
                    continue;
                }
                let reply =
                    tokio::time::timeout(PROBE_INTERVAL, self.socket.recv_from(&mut buffer));
                if let Ok(Ok((len, from))) = reply.await {
                    if from == peer && &buffer[..len] == PROBE {
                        return true;
                    }
                }
            }
        };
        matches!(tokio::time::timeout(budget, attempt).await, Ok(true))
    }
}
