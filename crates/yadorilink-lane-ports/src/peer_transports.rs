//! The per-peer transports a session opens streams through.
//!
//! A session talks to exactly one peer, so each of these is bound to one and
//! takes no peer argument — there is no way to pass the wrong one because
//! there is none to pass. What they share is a connection: blocks and service
//! RPCs both ride lanes of the same iroh connection to that peer,
//! which is what makes their flow-control separation mean anything.
//!
//! The connection is resolved per call rather than held. A link that has gone
//! away is redialled, and a peer whose address the netmap no longer carries
//! simply cannot be reached — the same answer production gives.

use std::sync::Arc;

use yadorilink_peer_session::ports::{
    BlockStreamTransport, PeerBlockStream, PeerServiceStream, ServiceStreamTransport,
};
use yadorilink_sync_substrate::Lane;
use yadorilink_transport::TransportError;

use crate::block_lane::LaneBlockStream;
use crate::service_lane::LaneServiceStream;

/// Where a connection to this session's peer comes from.
///
/// A trait rather than a concrete stack because the answer differs by caller
/// and the transports do not care: production resolves it through the netmap
/// and a link cache, a test dials a peer it already has an address for. What
/// both owe is the same thing — a live connection, or a reason there is none.
#[async_trait::async_trait]
pub trait PeerLinkSource: Send + Sync {
    /// A live connection to the peer, dialling if there is not one.
    async fn link(&self) -> Result<Arc<yadorilink_sync_substrate::PeerLink>, TransportError>;
}

/// Everything one session needs to reach its peer over the substrate.
#[derive(Clone)]
pub struct PeerTransports {
    source: Arc<dyn PeerLinkSource>,
}

impl PeerTransports {
    pub fn new(source: Arc<dyn PeerLinkSource>) -> Self {
        Self { source }
    }

    async fn open_lane_for(
        &self,
        lane: Lane,
        group_id: &str,
    ) -> Result<yadorilink_sync_substrate::LaneStream, TransportError> {
        let link = self.source.link().await?;
        // The group is the class the lane's budget is shared out between: a
        // large backlog for one folder must not put a later request for a
        // different one behind all of it. See `FairLaneGate`.
        let mut stream = link
            .open_lane_for(lane, group_id)
            .await
            .map_err(|error| TransportError::NoRoute(error.to_string()))?;
        // Every lane stream begins with the group it belongs to; the far end
        // authorizes against that and nothing it remembered.
        yadorilink_sync_protocol::session::open_lane(
            &mut stream,
            &yadorilink_sync_protocol::ports::GroupId(group_id.to_string()),
        )
        .await
        .map_err(|error| TransportError::NoRoute(error.to_string()))?;
        Ok(stream)
    }
}

#[async_trait::async_trait]
impl BlockStreamTransport for PeerTransports {
    async fn open(&self, group_id: &str) -> Result<Box<dyn PeerBlockStream>, TransportError> {
        Ok(Box::new(LaneBlockStream::new(self.open_lane_for(Lane::Block, group_id).await?)))
    }
}

#[async_trait::async_trait]
impl ServiceStreamTransport for PeerTransports {
    async fn open(&self, group_id: &str) -> Result<Box<dyn PeerServiceStream>, TransportError> {
        Ok(Box::new(LaneServiceStream::new(self.open_lane_for(Lane::Service, group_id).await?)))
    }
}
