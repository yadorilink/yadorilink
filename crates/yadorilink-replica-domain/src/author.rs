//! Author identities and the local record of an author's incarnation.
//!
//! An author is a registered device in one incarnation. Every sequence
//! number, frontier entry and dot is kept per [`AuthorId`], never per device,
//! so two copies of one replica that both keep writing are two authors, not
//! one author forking its own chain.

use ed25519_dalek::SigningKey;

use crate::codec::put_str;
use crate::ids::{AuthorSeq, DeltaHash, DeviceId, SyncPath};

/// One installation of a device's replica.
///
/// A fresh incarnation is minted at install, at restore from a backup, at
/// migration to another machine or database location, whenever the replica
/// detects that its identity no longer matches its environment, and when a
/// peer reports this replica's author (same incarnation) at a sequence
/// number above the local watermark. Two copies of one replica that both keep
/// writing would otherwise sign two different deltas at one dot, which
/// bounded retention cannot always detect; with distinct incarnations they
/// are two authors instead.
///
/// 16 random bytes, drawn from the operating system's CSPRNG. The all-zero
/// value is reserved and never names an author.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct IncarnationId(pub [u8; 16]);

impl IncarnationId {
    /// The reserved incarnation no author may carry.
    pub const RESERVED: IncarnationId = IncarnationId([0; 16]);
}

/// The author of a delta: a registered device in one incarnation.
///
/// Encoded as the device id (length-prefixed UTF-8) followed by the 16
/// incarnation bytes, and ordered in that field order.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AuthorId {
    pub device: DeviceId,
    pub incarnation: IncarnationId,
}

impl AuthorId {
    /// Appends the canonical encoding: the device id (length-prefixed
    /// UTF-8) followed by the 16 incarnation bytes.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        put_str(buf, self.device.as_str());
        buf.extend_from_slice(&self.incarnation.0);
    }

    /// Refuses the reserved incarnation, which no author may carry.
    pub fn validate(&self) -> Result<(), crate::codec::ChangeError> {
        if self.incarnation == IncarnationId::RESERVED {
            return Err(crate::codec::ChangeError::Malformed(format!(
                "author {} carries the reserved all-zero incarnation",
                self.device.as_str()
            )));
        }
        Ok(())
    }
}

impl std::fmt::Display for IncarnationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for AuthorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.device.as_str(), self.incarnation)
    }
}

/// SHA-256 digest of one authenticated namespace node.
///
/// The node encodings and domain tags this digest is taken over are fixed by
/// the namespace crate.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NodeDigest(pub [u8; 32]);

/// The most heads one author may have at one path.
///
/// Admission holds, and the author refuses to sign, a delta after which its
/// author's bucket at a touched path would hold more, so the live width at a
/// path is at most `MAX_SELF_HEADS * |authors|`. Only a full bucket
/// constrains the author: its next write landing at that path supersedes at
/// least one of its own heads there. Those are heads of the author's own
/// pre-state, so the write still supersedes only versions it observed.
pub const MAX_SELF_HEADS: usize = 2;

/// The present heads at one path, one bucket per author.
///
/// Each bucket holds one or [`MAX_SELF_HEADS`] delta hashes, strictly
/// ascending; an author with no head at the path has no bucket, and a path
/// with no bucket has no present entry. The namespace crate stores the
/// buckets of a path as an authenticated map keyed by author, with per-node
/// aggregate counts, so a step costs `O((|removed| + 1) log A)` bucket reads
/// for `A` authors, and a checkpoint is sealable (no two heads from one
/// author at any path) when the namespace root's duplicate-author count is
/// zero, read without enumerating heads.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct AuthorBuckets {
    pub by_author: std::collections::BTreeMap<AuthorId, Vec<DeltaHash>>,
}

/// Refusals of an author's own check before signing, against its own
/// pre-state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuthoringRefusal {
    /// The author asked to sign is not this replica's current author
    /// incarnation: a handle built before a rotation (or left behind by a
    /// rotation whose publication failed) names a retired incarnation.
    /// Signing under it would reuse a retired incarnation's sequence
    /// numbers, the fork [`Self::OwnAuthorAhead`] exists to prevent. The
    /// caller re-reads its author from the current incarnation.
    StaleAuthor { author: AuthorId, current: AuthorId },
    /// A peer reported this replica's own author (same incarnation) at a
    /// sequence number above the local watermark: another copy of this
    /// replica wrote under the same identity, for example after a clone or a
    /// restore. The replica refuses to author until it has rotated its
    /// incarnation.
    OwnAuthorAhead { author: AuthorId, local: AuthorSeq, reported: AuthorSeq },
    /// After the delta, the author's own bucket at `path` would hold `count`
    /// heads, more than [`MAX_SELF_HEADS`]; the author supersedes one of its
    /// own heads there first. Receivers hold such a delta, so an honest
    /// author never signs one.
    OwnBucketOverCap { path: SyncPath, count: usize },
}

/// Why a replica minted its current incarnation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IncarnationMintReason {
    /// A fresh database.
    Install,
    /// The database was restored from a backup.
    Restore,
    /// The database moved to another machine or location.
    Migration,
    /// The replica's recorded identity no longer matches its environment.
    IdentityMismatch,
    /// A peer reported this replica's author above the local watermark.
    OwnAuthorAhead,
    /// The replica moved onto a peer's checkpoint because its history had fallen
    /// behind what its peers keep, and left the changes of its previous
    /// incarnation behind (see `native_rebootstrap`).
    Rebootstrap,
}

/// A replica's record of its current incarnation and what it is bound to,
/// used to detect a copied or restored database.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IncarnationRecord {
    pub author: AuthorId,
    /// Random nonce of the database instance, kept (with the incarnation) in
    /// the `<db>.instance` sidecar beside the database so that a copied or
    /// restored database file is noticed. Rotated with every mint.
    pub db_instance_nonce: [u8; 16],
    /// A fingerprint of the machine the database was last opened on.
    pub machine_fingerprint: Vec<u8>,
    pub minted_reason: IncarnationMintReason,
    /// The incarnation this one replaced, if any.
    pub previous: Option<IncarnationId>,
}

/// Deterministic identities and keys for tests.
///
/// Production never signs through here: every key is derived from the device
/// id, so anyone can forge these.
#[doc(hidden)]
pub mod fixtures {
    use super::*;
    use sha2::{Digest, Sha256};

    /// A signing key derived from `device`, the same on every call.
    pub fn signing_key(device: &DeviceId) -> SigningKey {
        let mut hasher = Sha256::new();
        hasher.update(b"yadorilink fixture key\0");
        hasher.update(device.as_str().as_bytes());
        SigningKey::from_bytes(&hasher.finalize().into())
    }

    /// `device` in the incarnation whose 16 bytes are all `incarnation`.
    pub fn author(device: &str, incarnation: u8) -> AuthorId {
        AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([incarnation; 16]) }
    }
}
