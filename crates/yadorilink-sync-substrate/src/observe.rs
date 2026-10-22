//! What a node tells its owner about the connections it dials and accepts.
//!
//! A node does not keep its connections: reconciliation dials one per pass and
//! drops it, the bulk lanes keep another, and an accepted connection lives as
//! long as the peer keeps it. Whoever wants to know whether a peer is
//! reachable right now has to hear about every one of them as it happens,
//! which only the node can offer -- asking afterwards finds nothing, because a
//! connection that is not held is gone.
//!
//! An observation is never an authorization input. It arrives after admission
//! has already decided, and nothing here can change that decision.

use std::fmt;
use std::sync::Arc;

use crate::link::PeerLink;
use crate::peer::PeerId;

/// Why a dial ended without a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialFailure {
    /// No address was known for the peer, so nothing was tried.
    NoAddress,
    /// The peer answered and turned the connection down.
    Refused,
    /// Nothing answered in time, or the attempt was abandoned before it
    /// finished.
    NoResponse,
}

/// One moment in the life of a connection a node dials or accepts.
#[derive(Debug)]
pub enum LinkEvent<'a> {
    /// A dial to this peer has started.
    Dialing(PeerId),
    /// The dial to this peer that last reported [`LinkEvent::Dialing`] ended.
    /// Reported exactly once per dial, including one whose caller gave up on
    /// it before it finished.
    Dialed(PeerId, Result<&'a PeerLink, DialFailure>),
    /// A connection from this peer passed admission and is about to be
    /// served.
    Accepted(&'a PeerLink),
}

/// Told about every connection a node dials or accepts.
///
/// Called inline on the dial and accept paths, so it must not block. It is
/// handed a borrowed link: keeping a clone keeps the connection open, which is
/// the observer's decision to make and not a side effect of being told.
#[derive(Clone)]
pub struct LinkObserver(Arc<dyn Fn(LinkEvent<'_>) + Send + Sync>);

impl LinkObserver {
    pub fn new(observe: impl Fn(LinkEvent<'_>) + Send + Sync + 'static) -> Self {
        Self(Arc::new(observe))
    }

    pub(crate) fn notify(&self, event: LinkEvent<'_>) {
        (self.0)(event);
    }
}

impl fmt::Debug for LinkObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinkObserver")
    }
}

/// A dial the observer has been told started, whose end it must also be told.
///
/// The end is reported on drop when nothing else reported it: a caller that
/// wraps a dial in a deadline drops the dial's future mid-flight, and an
/// observer left believing that dial is still running would show the peer as
/// being connected to forever.
pub(crate) struct DialInFlight {
    observer: Option<LinkObserver>,
    peer: PeerId,
}

impl DialInFlight {
    pub(crate) fn start(observer: Option<&LinkObserver>, peer: PeerId) -> Self {
        if let Some(observer) = observer {
            observer.notify(LinkEvent::Dialing(peer));
        }
        Self { observer: observer.cloned(), peer }
    }

    pub(crate) fn finish(mut self, outcome: Result<&PeerLink, DialFailure>) {
        if let Some(observer) = self.observer.take() {
            observer.notify(LinkEvent::Dialed(self.peer, outcome));
        }
    }
}

impl Drop for DialInFlight {
    fn drop(&mut self) {
        if let Some(observer) = self.observer.take() {
            observer.notify(LinkEvent::Dialed(self.peer, Err(DialFailure::NoResponse)));
        }
    }
}
