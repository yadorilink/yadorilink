//! The independent flow-control domains of `YadoriSyncProtocol`.
//!
//! A lane is a *class* of QUIC bidirectional streams within one connection,
//! not a single stream. QUIC applies flow control per stream, so a stalled or
//! saturated lane cannot head-of-line block another one. This is the
//! structural replacement for the single shared control stream, on which a
//! bulk `ChangeBatch` could indefinitely starve a `HeadsAnnounce`.
//!
//! Splitting streams removes *stream-level* head-of-line blocking only.
//! Connection-level congestion and flow-control credit stay shared, so each
//! lane class also carries a concurrency limit (see [`LaneLimits`]). Should
//! block transfer alone be measured to exhaust connection-level credit, the
//! next step is a separate ALPN and connection for it — not a return to one
//! shared stream.
//!
//! Native replication does not ride these lanes: it has its own ALPN and
//! connection lifecycle (see `native_replication_transport`).

use std::fmt;

/// A flow-control domain within one peer connection.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lane {
    /// File block / content hydration traffic. The bulkiest lane by orders of
    /// magnitude.
    Block,
    /// Small request/response service RPCs: version-present, handoff leases
    /// and tickets, durability.
    ///
    /// Durability has no RPC of its own — it is a `for_handoff`
    /// version-present query — so it rides here by construction rather than
    /// by being moved.
    ///
    /// One stream per logical RPC, deliberately — not one shared stream with
    /// a receive loop and a request-id map behind it. That shape is what the
    /// lane classes exist to remove, and rebuilding it here on iroh would put
    /// it back: a slow RPC would again delay every other one, and the
    /// correlation table would again be a thing that can leak, mismatch or
    /// grow. A QUIC stream already *is* the correlation between a request and
    /// its response.
    ///
    /// Classified by shape rather than by which legacy frame carried it:
    ///
    /// ```text
    ///   small request / control metadata  →  Service
    ///   content bytes                     →  Block
    /// ```
    Service,
}

impl Lane {
    /// Every lane, in declaration order.
    pub const ALL: [Lane; 2] = [Lane::Block, Lane::Service];

    /// The one-byte tag written as the first byte of a lane's stream so the
    /// accepting side can dispatch a newly accepted stream to its handler.
    pub const fn tag(self) -> u8 {
        match self {
            Lane::Block => 3,
            Lane::Service => 4,
        }
    }

    /// Inverse of [`Lane::tag`]. Returns `None` for an unknown tag, which a
    /// peer must treat as a protocol violation rather than as a lane to guess.
    pub const fn from_tag(tag: u8) -> Option<Lane> {
        match tag {
            3 => Some(Lane::Block),
            4 => Some(Lane::Service),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Lane::Block => "block",
            Lane::Service => "service",
        }
    }
}

impl fmt::Debug for Lane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Display for Lane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Per-connection concurrency budget for each lane class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneLimits {
    /// Concurrent block/content transfers.
    pub block: usize,
    /// Concurrent service RPCs.
    ///
    /// Bounded for a different reason than the bulk lanes: a service RPC is
    /// small on the wire but can cost a task and a database round trip, so
    /// without a budget a peer opening streams in a loop turns into unbounded
    /// work here. Higher than the bulk lanes because each one is short.
    pub service: usize,
}

impl LaneLimits {
    /// The budget for `lane`.
    pub const fn for_lane(&self, lane: Lane) -> usize {
        match lane {
            Lane::Block => self.block,
            Lane::Service => self.service,
        }
    }
}

impl Default for LaneLimits {
    fn default() -> Self {
        // Small enough that a peer cannot convert bulk concurrency into
        // connection-level credit exhaustion, large enough to keep the link
        // busy while any one transfer is waiting on storage.
        Self { block: 8, service: 16 }
    }
}

#[cfg(test)]
mod tests;
