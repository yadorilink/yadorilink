//! Errors crossing the substrate adapter boundary.
//!
//! These deliberately do not leak `p2panda_net` or `iroh` error types: the
//! whole point of this crate is that a p2panda or iroh upgrade is absorbed
//! here and nowhere else.

use thiserror::Error;

use crate::lane::Lane;

#[derive(Debug, Error)]
pub enum SubstrateError {
    /// The networking substrate could not be started.
    #[error("failed to start networking substrate: {0}")]
    Startup(String),

    /// A connection to the remote peer could not be established.
    #[error("failed to connect to peer: {0}")]
    Connect(String),

    /// A lane stream could not be opened or accepted.
    #[error("failed to open lane {lane}: {reason}")]
    Lane { lane: Lane, reason: String },

    /// A peer sent a stream whose first byte is not a known lane tag.
    #[error("peer opened a stream with unknown lane tag {0}")]
    UnknownLaneTag(u8),

    /// A stream could not be accepted from the peer.
    #[error("failed to accept a lane stream: {reason}")]
    Accept { reason: String },

    /// Reading from or writing to a lane failed.
    #[error("lane {lane} i/o failed: {reason}")]
    LaneIo { lane: Lane, reason: String },

    /// A Track Send stream could not be opened, accepted or finished.
    #[error("track send stream failed: {0}")]
    TrackSend(String),

    /// A native-replication stream could not be opened, accepted, read or
    /// finished.
    #[error("native replication stream failed: {0}")]
    NativeReplication(String),
}
