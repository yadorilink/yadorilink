//! Presenting a substrate lane through a peer session's ports.
//!
//! A `PeerSyncSession` reaches its peer through ports — a block stream, a
//! service stream, a snapshot fetch — and the substrate offers lanes of one
//! iroh connection. These are the adapters between the two, and nothing else:
//! no policy, no authorization, no knowledge of what rides them.
//!
//! # Why its own crate
//!
//! They lived in `yadorilink-daemon` first, which made the daemon the only
//! thing that could produce a session able to reach a peer. That was fine
//! while a session could also fall back to a legacy channel, and wrong once
//! it could not: a peer session's transports are not optional, so a test that
//! builds a session has to build real ones too, and a test in
//! `yadorilink-peer-session` cannot reach into the daemon.
//!
//! The alternative was a null transport for fixtures — a session that exists
//! and can never carry anything. That is the state this cutover removed from
//! production, and reintroducing it under a test-only name would leave every
//! future constructor and lifecycle change unchecked by exactly the tests
//! meant to check it.
//!
//! So the adapters sit below both: the daemon depends on this crate, and
//! `yadorilink-peer-session` dev-depends on it, which Cargo permits and which
//! keeps one construction path for production and fixtures alike.

pub mod block_lane;
pub mod directory;
pub mod peer_transports;
pub mod service_lane;
/// Network faults for the simulated substrate, injected at the carrier.
#[cfg(feature = "test-support")]
pub mod sim_fault;
/// A real substrate endpoint for tests that build their own sessions.
#[cfg(feature = "test-support")]
pub mod testing;

pub use block_lane::LaneBlockStream;
pub use directory::{PeerDirectory, StaticPeerDirectory};
pub use peer_transports::{PeerLinkSource, PeerTransports};
pub use service_lane::{LaneServiceStream, MAX_SERVICE_MESSAGE_BYTES};

#[cfg(test)]
mod block_lane_tests;
#[cfg(test)]
mod service_lane_tests;
