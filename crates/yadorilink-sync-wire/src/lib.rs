//! Peer wire codec/frame layer for `yadorilink`'s sync protocol: converts
//! between raw wire bytes and protobuf-free domain frames (the block-stream
//! headers).

mod error;
mod frame;
mod protobuf;

pub use error::WireError;
pub use frame::{
    AuthorizationCheckpointEnvelopeFrame, AuthorizationMerkleProofFrame, BlockRequestHeaderFrame,
    BlockResponseHeaderFrame, BlockResponseOutcomeFrame, PublishedChangeFrame,
};
pub use protobuf::ProtobufPeerWireCodec;

/// The wire's `Compression` enum values, owned here (not re-exported from
/// `yadorilink_ipc_proto::sync::Compression` at call sites) so that
/// consumers needing only these two values don't need to reach through a
/// generated protobuf type to name them.
///
/// These are not a negotiated capability: every peer that reaches a session
/// is the same protocol generation and understands both. A sender picks
/// between them per payload, choosing raw whenever compressing would make
/// the payload larger.
pub const COMPRESSION_NONE: i32 = 0;
pub const COMPRESSION_ZSTD: i32 = 1;

#[cfg(test)]
mod tests;
