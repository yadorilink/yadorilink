//! The one thing local convergence needs a peer for.
//!
//! Convergence work is local: it reads this device's index, writes this
//! device's disk, and proves what it wrote. Three things it cannot do
//! alone -- name the peer a record arrived from, hand an adopted record
//! to that peer session's forwarding channel, and obtain a block this
//! device does not have.
//!
//! That is this module, and it is deliberately the whole crate boundary
//! between a peer session and the convergence executor that runs in
//! `yadorilink-daemon`. Nothing about how a session is implemented
//! appears here: no wire types, no fetch state machine, no measurement
//! plumbing. A fetch reports its outcome and how long it spent on the
//! wire; what the caller does with either is the caller's business.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;

use yadorilink_replica_domain::file::BlockInfo;

use crate::error::PeerSessionError;

/// What asking a peer for one block produced.
pub enum BlockFetch {
    /// The peer served the block, and it hashed to the key it was asked
    /// for. Verification happens before this is returned, so a caller
    /// never sees bytes that failed their own hash.
    Fetched { hash: Vec<u8>, data: Bytes },
    /// The peer does not have it, would not serve it, or never answered.
    /// To the caller these are the same fact -- the block did not arrive,
    /// try elsewhere or later -- so they stay one variant.
    Missing,
    /// The peer refused definitively, for the one reason that is evidence
    /// about *content* rather than about permission: it holds no verified
    /// provenance for this block in this group.
    ///
    /// Separate from `Missing` because it is the only fetch answer worth
    /// keeping. A `NotFound`, a timeout or a busy peer says nothing --
    /// the block may arrive on the next attempt. Nor does any other
    /// refusal: an authorization failure or a malformed request proves
    /// only that this peer would not answer, not that the bytes are
    /// unobtainable, and recording one as if it did would let a
    /// permissions problem be read as durability evidence.
    ///
    /// The caller persists it, against the version it asked for, because
    /// the caller is the side that owns this device's durable state. The
    /// session reports what the peer said; it does not write it down.
    VerifiedRefusal {
        /// The refusal reason exactly as the peer worded it, for the
        /// durable record.
        reason: String,
    },
}

/// A completed fetch attempt.
pub struct FetchedBlock {
    pub outcome: BlockFetch,
    /// Wall-clock spent waiting on the wire, summed across retries for
    /// this one block.
    ///
    /// Reported as a plain duration rather than by handing the session a
    /// caller-owned timer to write into: the caller keeps whatever
    /// accounting it keeps, and the boundary stays free of it.
    pub wire_wait: Duration,
}

/// What the convergence executor needs back from whatever is driving it.
pub trait ConvergenceDriver: Send + Sync {
    /// The peer this work arrived from. Used for tracing, and as the
    /// origin a record falls back to when it carries none of its own.
    fn peer_device_id(&self) -> &str;

    /// Obtains one block this device does not have.
    ///
    /// Takes no version: the session asks a peer for bytes by hash, and
    /// which version wanted them is the caller's bookkeeping. It used to
    /// take one only so the session could write a refusal against it,
    /// which is now the caller's to write -- see
    /// `BlockFetch::VerifiedRefusal`.
    fn fetch_block<'a>(
        &'a self,
        group_id: &'a str,
        file_path: &'a str,
        block: &'a BlockInfo,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<FetchedBlock, PeerSessionError>> + Send + 'a>>;
}
