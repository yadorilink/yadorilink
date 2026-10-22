//! Device identity and the small pieces of the peer protocol that are not a
//! transport.
//!
//! Peer connectivity -- dialling, NAT traversal, path selection, relay
//! fallback and LAN discovery -- belongs entirely to the iroh endpoint in
//! `yadorilink-sync-substrate`. What this crate supplies is the device
//! signing key pair and its OS keyring storage, the block-stream length
//! framing every lane shares, the netmap diff, `TransportError`, and the
//! simulation socket shim (`sim_net`).

pub mod block_stream;
mod error;
mod key_secret_store;
mod keys;
mod peer_channel;
/// Which UDP socket a simulated control plane is built on -- the one place
/// the native and turmoil builds differ.
pub mod sim_net;

pub use block_stream::{MAX_BLOCK_STREAM_BODY_BYTES, MAX_BLOCK_STREAM_HEADER_BYTES};
pub use error::TransportError;
pub use keys::{verifying_key_from_bytes, DeviceSigningKeyPair, KeyLoadError};
pub use peer_channel::{diff_netmap, NetmapDiff, NetmapSnapshot};
