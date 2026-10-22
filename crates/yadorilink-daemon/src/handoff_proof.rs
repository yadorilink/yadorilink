//! The value a destructive action must hold before it may proceed.
//!
//! This type exists to make one distinction impossible to blur: the
//! difference between *this device has just proved, against one named peer,
//! that every byte of this group survives elsewhere* and *this device last
//! heard something encouraging about this group*.
//!
//! Both facts are useful and both are wanted. Only the first may authorize
//! giving up a durable copy. Given the same Rust shape — a `bool`, or an
//! `Option<([u8; 32], Option<String>)>` — nothing but convention would keep
//! a background health check out of an unlink gate, and a background job
//! reusing the action-time check would issue thousands of whole-file
//! re-reads every sweep.
//!
//! See `crate::background_custody` for the deliberately weaker sibling:
//! background evidence may inform status, never authorize a destructive
//! action.

/// Proof that, at the moment it was constructed, one specific named peer
/// durably held **every** durability root of a folder group — verified by
/// that peer reading each block back off its own disk and re-checking its
/// checksum, not by any form of existence check, cached checksum, or
/// metadata comparison.
///
/// # What holding one of these means
///
/// Every clause was true at construction time:
///
/// 1. A **single** peer answered for the whole set. Not a union of peers:
///    two peers each holding half a group leave the group with zero complete
///    durable copies, so coverage is decided per peer.
/// 2. That peer confirmed each root by locating a non-deleted version at
///    that path whose **recomputed** version hash equals the queried one,
///    matching the ordered block list and every declared block size,
///    checking block provenance for the group, and reading every block back
///    in full to re-verify its checksum.
/// 3. That peer was a netmap-authorized full-replica writer for the group
///    both immediately before and immediately after every round-trip, and
///    the local membership generation did not move across any of them.
/// 4. [`Self::root_digest`] is the digest of exactly the root set proven —
///    which a caller about to commit must re-derive and compare immediately
///    before committing, since the set can move after the proof is taken.
///
/// # What holding one of these does NOT mean
///
/// It says nothing about any later instant. It is evidence about the moment
/// it was made and nothing else. There is deliberately no `Clone`, no
/// serialization, and no cache anywhere in this crate that can hold one: a
/// gate that needs this fact produces it, uses it, and drops it. Anything
/// that outlives the call is a claim about the past wearing the clothes of
/// a claim about now.
#[derive(Debug)]
pub struct StrongHandoffProof {
    root_digest: [u8; 32],
    peer_device_id: Option<String>,
    membership_generation: u64,
}

impl StrongHandoffProof {
    /// Records a proof that has just been completed.
    ///
    /// Confined by the architecture manifest to the one function that can
    /// actually establish the clauses in this type's doc comment
    /// (`DaemonState::full_replica_handoff_ready`). The fields are private
    /// as well, so the confinement is on the only way in, not merely on the
    /// tidy way in.
    pub(crate) fn new(
        root_digest: [u8; 32],
        peer_device_id: Option<String>,
        membership_generation: u64,
    ) -> Self {
        Self { root_digest, peer_device_id, membership_generation }
    }

    /// The digest of exactly the durability-root set this proof covers.
    pub fn root_digest(&self) -> [u8; 32] {
        self.root_digest
    }

    /// The peer that confirmed coverage, or `None` for a **vacuous** proof.
    ///
    /// A vacuous proof is a real one: the group's durability-root set was
    /// genuinely empty, so there is nothing to hand off and no peer needed
    /// to confirm anything. It is not a weaker answer, but it does have one
    /// consequence a caller must respect — there is no target device to name
    /// for a lease-guarded commit, and it must not clear a post-`--force`
    /// durability latch, because "everything expired or was deleted" and
    /// "this group never had anything" look identical from here.
    pub fn peer_device_id(&self) -> Option<&str> {
        self.peer_device_id.as_deref()
    }

    /// Takes ownership of the confirming peer's device id.
    pub fn into_peer_device_id(self) -> Option<String> {
        self.peer_device_id
    }

    /// The membership generation this proof was taken under, and held
    /// across every round-trip that built it.
    #[allow(dead_code, reason = "carried for diagnostics and for callers that re-check it")]
    pub fn membership_generation(&self) -> u64 {
        self.membership_generation
    }
}
