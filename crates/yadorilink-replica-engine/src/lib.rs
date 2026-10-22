//! Pure replica-engine policy: custody/durability evidence checks, conflict
//! and namespace resolution, native bootstrap snapshot shapes,
//! with zero I/O, SQL, wire, or async runtime dependency.
//!
//! Depends only on `yadorilink-replica-domain`. The daemon implements this
//! crate's port ([`ports::DurabilityEvidencePort`]) as a thin adapter over
//! its own storage.

pub mod authorized_writer;
pub mod conflict;
pub mod custody;
mod engine;
pub mod error;
pub mod handoff_lease;
pub mod outcomes;
pub mod ports;

use std::sync::Arc;

pub use engine::{DurableVersionQuery, PeerReplicaEngine};
pub use ports::{CustodyLeasePort, DurabilityEvidencePort};

/// `PeerReplicaEngine`'s port dependency.
#[derive(Clone)]
pub struct ReplicaEngineDependencies {
    pub durability: Arc<dyn DurabilityEvidencePort>,
    pub leases: Arc<dyn CustodyLeasePort>,
}
