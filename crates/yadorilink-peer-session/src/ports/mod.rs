//! Capability-port traits `PeerSyncSession` needs from the runtime that
//! composes it: block-serving authorization against replica state
//! (`BlockServeAuthorizationPort`) and the stream lanes to one peer
//! (`SessionTransports`), plus an in-memory implementation of the latter for
//! tests (`InMemoryPeerChannel`).

mod block_serve_authorization;
#[cfg(any(test, feature = "test-support"))]
mod in_memory_channel;
mod peer_message_channel;
mod peer_replica_state;

pub use block_serve_authorization::{BlockServeAuthorization, BlockServeAuthorizationPort};
#[cfg(any(test, feature = "test-support"))]
pub use in_memory_channel::{
    in_memory_transports, InMemoryBlockStream, InMemoryPeerChannel, InMemoryServiceStream,
};
pub use peer_message_channel::{
    BlockStreamTransport, PeerBlockStream, PeerServiceStream, ServiceStreamTransport,
    SessionTransports,
};
pub use peer_replica_state::{
    CurrentRowSnapshot, ExactActualState, ExpectedAuthoring, FinishedProjectedUpsert,
    OpenMaterializationIntent, PreparedProjectedDelete, MATERIALIZATION_IN_FLIGHT_STATE,
};
pub use yadorilink_local_storage::BlockContentStore;
