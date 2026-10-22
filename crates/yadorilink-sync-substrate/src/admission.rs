//! Who is allowed to open a sync lane with this device.
//!
//! The TLS handshake proves the remote holds the private key for the
//! [`PeerId`] it claims. That is authentication, and it is all iroh can
//! offer: it says the peer is who it says it is, and nothing at all about
//! whether this device has any business talking to them. Without a second
//! check, any stranger who learns an address gets a live lane, because
//! "I am a valid Ed25519 keyholder" is a statement every keyholder on
//! earth can make truthfully.
//!
//! So admission asks the only question authentication leaves open: is this
//! authenticated identity one of *our* devices? A remote is admitted when
//! its [`PeerId`] resolves to a device this node has pinned through the
//! coordination plane, and refused otherwise.
//!
//! # Why this is a required argument and not an `Option`
//!
//! [`SubstrateNode::spawn`](crate::SubstrateNode::spawn) takes a policy by
//! value with no default. That is deliberate and is the whole of the
//! fail-closed guarantee: there is no way to spawn a node without stating
//! who it will talk to, so admission cannot be lost by forgetting to
//! configure it. A `None`-means-allow-everything default would put the
//! secure behaviour behind an opt-in, and the one call site that forgets
//! is then indistinguishable from one that deliberately opened up.
//!
//! # What this is *not*
//!
//! Admission decides whether a carrier-level link exists. It says nothing
//! about what may be done over that link: whether a peer may read a folder
//! group, or whether a Change it offers may be admitted to history, stays
//! with the replica and policy layers, which verify authorship against a
//! group's own policy chain and never consult the carrier. An admitted
//! peer is a peer we will exchange bytes with, not a peer we trust.

use std::fmt::Debug;
use std::sync::Arc;

use crate::peer::PeerId;

/// Decides whether an authenticated remote may be given a link.
///
/// Implementations should answer from live state rather than a set
/// captured at startup. Revocation is the reason: a device removed from
/// the coordination plane must stop being admitted on the next connection
/// attempt, and a snapshot taken when the node spawned would keep letting
/// it in for the life of the process.
pub trait PeerAdmission: Debug + Send + Sync + 'static {
    /// `true` if `peer` may open a sync lane with this device.
    ///
    /// Called once per inbound connection, before any link is exposed.
    /// Must not block: it runs on the accept path, so a slow answer stalls
    /// every other peer's connection behind it.
    fn admit(&self, peer: &PeerId) -> bool;
}

/// Admits nobody.
///
/// The honest policy for a node that has no peers to talk to yet, and the
/// right default for a test that only needs a node to exist. Named rather
/// than expressed as an absent policy so that "this node accepts no
/// inbound connections" is a visible claim at the call site.
#[derive(Debug, Clone, Copy)]
pub struct AdmitNone;

impl PeerAdmission for AdmitNone {
    fn admit(&self, _peer: &PeerId) -> bool {
        false
    }
}

/// Admits any authenticated peer.
///
/// Available only under `test-support`, and deliberately so: this is
/// exactly the behaviour the gate exists to prevent, and it must not be
/// reachable from a production build even by accident. A test that uses it
/// is asserting something other than admission.
#[cfg(feature = "test-support")]
#[derive(Debug, Clone, Copy)]
pub struct AdmitAnyAuthenticated;

#[cfg(feature = "test-support")]
impl PeerAdmission for AdmitAnyAuthenticated {
    fn admit(&self, _peer: &PeerId) -> bool {
        true
    }
}

/// Adapts a closure over live state into a policy.
///
/// The daemon's peer set lives in `DaemonState`, which this crate cannot
/// name. Rather than invert that dependency for one predicate, the daemon
/// hands over a closure that reads its own pinned-key map on each call --
/// which is also what keeps revocation prompt.
pub struct AdmitWhen<F>(F);

impl<F> AdmitWhen<F>
where
    F: Fn(&PeerId) -> bool + Send + Sync + 'static,
{
    // Callers only ever want the type-erased policy handle; returning it
    // directly keeps every call site a one-liner.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(predicate: F) -> Arc<dyn PeerAdmission> {
        Arc::new(Self(predicate))
    }
}

impl<F> Debug for AdmitWhen<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The closure has no useful representation, and printing one would
        // invite logging the peer set it closes over.
        f.write_str("AdmitWhen(..)")
    }
}

impl<F> PeerAdmission for AdmitWhen<F>
where
    F: Fn(&PeerId) -> bool + Send + Sync + 'static,
{
    fn admit(&self, peer: &PeerId) -> bool {
        (self.0)(peer)
    }
}

#[cfg(test)]
mod tests;
