//! The vocabulary of one write to a user-visible name: what is being done
//! ([`WriteSpec`]), the steps every such write goes through
//! ([`StepEvent`]) and how it ended ([`ProofOutcome`]).
//!
//! A write is ordered as: retain, prepare (one transaction), stage, check,
//! publish, observe, prove (one transaction), settle. The lanes decide *what*
//! to write; this module names the order so that a lane's sequence of durable
//! steps can be recorded and compared with another's.
//!
//! Today only the eager receive lane reports into it, and it does so
//! passively: [`trace::emit`] observes the lane's existing call sites and
//! changes nothing about what they do. In a production build the events compile to
//! nothing.

pub mod failpoint;
pub mod ingest;
pub mod trace;

use yadorilink_replica_domain::ids::VersionHash;

/// What is being done to one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // only `Materialize` has a lane on the op so far
pub enum OpKind {
    Materialize,
    SingleObject,
    Delete,
    Evict,
    Restore,
    Ingest,
}

/// The object a write leaves at the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TargetObject {
    /// A regular file with this version's bytes.
    Content(VersionHash),
    Absent,
}

/// How the version a write replaces was accounted for. A write states it;
/// there is no default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Retention {
    /// Its bytes were put in the store (or were never on this device) before
    /// the row stopped being current.
    Proofs,
    /// The version was accounted for when the sync superseded its row (kept in the store, or
    /// deliberately given up, for instance for lack of space); this write does not decide again.
    DecidedAtSupersession,
    /// The path holds the user's own edit, kept by the capture that authored it.
    OwnEdit,
    /// Nothing to keep, for the stated reason (a fresh path, store-first custody).
    NotNeeded(&'static str),
}

/// A write, as a plain description. Built by the lane; the op never decides
/// policy (what to write, which version wins).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSpec {
    pub kind: OpKind,
    pub group_id: String,
    pub path: String,
    pub target: TargetObject,
    pub retention: Retention,
    /// Whether the obligation engine handed the attempt a claim to close in
    /// the proof transaction.
    pub claimed: bool,
}

/// How a write was proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ProofOutcome {
    /// The exact object is on disk and recorded.
    Exact,
    /// The object is verifiably gone and its tombstone is recorded.
    Absent,
    /// The object is replaced by a recorded placeholder (an eviction); the row stays, `Remote`.
    Placeholder,
    /// The object is a non-empty directory kept on disk (its entry's tombstone is recorded).
    Retained,
    /// The object is gone and its row erased without a tombstone (a displaced local-only copy).
    LocallyErased,
}

/// What the proof transaction did with the write's intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentSettlement {
    /// Cleared in the proof transaction.
    Cleared,
    /// Left for the window's flush barrier to clear.
    FlushPending,
}

/// One step of a write that reached a durable or committed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepEvent {
    /// Transaction one is committed: intent open, row in flight, fence bumped.
    Prepared,
    /// The bytes are under their name. `names_deferred` is set when the
    /// rename was left unflushed for the window's barrier; `landed_marked`
    /// whether the intent already says the name is durable.
    Published { names_deferred: bool, landed_marked: bool },
    /// Transaction two is committed.
    Proven { outcome: ProofOutcome, intent: IntentSettlement, obligation_closed: bool },
    /// The flush barrier made the names durable and cleared the intent that
    /// `Proven` left `FlushPending`.
    Settled,
    /// Ingest (OS to store): the upload is journaled by operation identity.
    IngestJournaled,
    /// Ingest: the upload's blocks and their provenance are durable in the store.
    IngestStoreDurable,
    /// Ingest: the apply transaction (view fence, change, apply log, journal row) committed.
    IngestApplied,
    /// Provider hand-off (store to OS bytes): the verified bytes are in `staging/`.
    ProviderStaged,
    /// Hand-off: the sticky served record is durable, before any name exists.
    ProviderMayServeRecorded,
    /// Hand-off: the file is named in `handoff/` and its directory is synced.
    ProviderHandoffNamed,
    /// Hand-off: the response reached the extension.
    ProviderResponded,
    /// Hand-off: the evidence row is durable.
    ProviderEvidenceRecorded,
}
