//! A relay this process owns, for tests that have to prove something about
//! the relay path.
//!
//! Production relays through iroh's public infrastructure. A test must not:
//! a suite whose result depends on reachable third-party servers reports the
//! network's state as often as the code's, and a relay test that quietly falls
//! back to a direct path when that infrastructure is unreachable reports
//! nothing at all. So the split is explicit:
//!
//! ```text
//!   production   RelayMode::Default    →  public iroh relays
//!   tests        RelayMode::Custom     →  this in-process relay
//! ```
//!
//! What stays identical across the two is everything above the relay: the
//! endpoint, the ALPN, the lanes, and — the point of the exercise — admission,
//! which takes no parameter naming a carrier at all.

use crate::node::NetworkConfig;

/// A relay server running inside this test process.
///
/// Bound to loopback on an ephemeral port, with a self-signed certificate the
/// configurations below tell clients to accept. Shutting down when dropped, so
/// a test that panics does not leave one behind.
#[derive(Debug)]
pub struct InProcessRelay {
    url: iroh::RelayUrl,
    // Dropping the server stops it. Held for exactly that.
    _server: iroh_relay::server::Server,
}

impl InProcessRelay {
    /// Start one, or fail loudly.
    ///
    /// A test that cannot get a relay has nothing to say about relaying, so
    /// this returns the error rather than degrading to a direct path.
    pub async fn start() -> Result<Self, crate::error::SubstrateError> {
        let (_map, url, server) = iroh::test_utils::run_relay_server()
            .await
            .map_err(|err| crate::error::SubstrateError::Startup(err.to_string()))?;
        Ok(Self { url, _server: server })
    }

    /// This relay's URL, as a peer address records it.
    pub fn url(&self) -> &iroh::RelayUrl {
        &self.url
    }

    /// A node that prefers a direct path and falls back to this relay —
    /// production's own shape, with the public infrastructure swapped out.
    pub fn direct_or_relay(&self) -> NetworkConfig {
        NetworkConfig::direct_or_relay_for_tests([self.url.clone()])
    }

    /// A node whose only carrier is this relay.
    ///
    /// See [`NetworkConfig::relay_only_for_tests`] for why this removes the IP
    /// transports rather than merely withholding a peer's direct addresses.
    pub fn relay_only(&self) -> NetworkConfig {
        NetworkConfig::relay_only_for_tests([self.url.clone()])
    }
}

/// An address directory shared by every node in one test process.
///
/// Production's directory is the coordination plane. A test has no plane, so
/// this stands in for it: each node publishes into the same map, and resolves
/// out of it. That is the whole of what the plane does for reachability, which
/// is why a test using this exercises the real path rather than a shortcut --
/// the nodes still connect by endpoint id, and iroh still decides how to
/// reach them.
#[derive(Debug, Default, Clone)]
pub struct SharedAddressBook {
    entries: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<[u8; 32], AddressEntry>>>,
}

/// One node's published direct addresses and relay URLs.
type AddressEntry = (Vec<std::net::SocketAddr>, Vec<String>);

impl SharedAddressBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Waits until `peer` has published an address into this book.
    ///
    /// iroh publishes asynchronously, from its socket actor, and
    /// `publish_my_addr` deliberately publishes nothing at all while the
    /// address set is still empty. A test that dials the instant a node is
    /// spawned can therefore resolve nothing -- which under one test thread is
    /// hidden by the slack between tests, and under several is a dial with no
    /// address to use.
    ///
    /// Waiting here rather than retrying the dial keeps the failure honest: if
    /// an address never arrives, this is what fails, and it says so.
    pub async fn wait_published(&self, peer: crate::peer::PeerId) {
        use crate::directory::AddressDirectory as _;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some((direct, relays)) = self.resolve(peer) {
                if !direct.is_empty() || !relays.is_empty() {
                    return;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "an endpoint never published an address into the shared book"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}

impl crate::directory::AddressDirectory for SharedAddressBook {
    fn publish(
        &self,
        peer: crate::peer::PeerId,
        direct: Vec<std::net::SocketAddr>,
        relays: Vec<String>,
    ) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(*peer.as_bytes(), (direct, relays));
    }

    fn resolve(
        &self,
        peer: crate::peer::PeerId,
    ) -> Option<(Vec<std::net::SocketAddr>, Vec<String>)> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).get(peer.as_bytes()).cloned()
    }
}
