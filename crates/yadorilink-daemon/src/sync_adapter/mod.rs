//! The daemon's transport stack: the iroh endpoint, lane routing, the peer
//! directory and the per-peer block/service transports.

pub mod address_directory;
mod daemon_directory;

pub mod driver;
pub mod sync_stack;

pub use daemon_directory::DaemonPeerDirectory;
pub use driver::PeerSessionDriver;
pub use sync_stack::{SyncStack, SyncStackError};
// The lane adapters live in `yadorilink-lane-ports` so that anything building
// a `PeerSyncSession` -- this crate or a fixture below it -- constructs the
// same real transports. Re-exported here because every existing caller in
// this crate names them through `sync_adapter`.
pub use yadorilink_lane_ports::{
    LaneBlockStream, LaneServiceStream, PeerDirectory, PeerLinkSource, PeerTransports,
    StaticPeerDirectory, MAX_SERVICE_MESSAGE_BYTES,
};
/// Re-exported so a caller configuring a stack does not have to depend on the
/// substrate crate directly -- this module is the seam, and naming iroh above
/// it is what the substrate boundary exists to prevent.
pub use yadorilink_sync_substrate::NetworkConfig;
