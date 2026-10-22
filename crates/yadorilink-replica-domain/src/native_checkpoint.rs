//! `NativeCheckpoint`: the signed summary a sealer commits to, so a replica
//! with no state (a new device, a new member, one whose database was lost) can
//! bootstrap from "a sealed complete state + the deltas that follow" rather
//! than the full history.
//!
//! The sealer is a writer: this type carries its own signature, made with the
//! sealing writer's device key and verified against it; no quorum is required; cadence is
//! runtime policy, not encoded here — this type is the wire object alone. A
//! checkpoint never justifies discarding a delta and is never merged into the
//! state of a replica that already holds some.
//!
//! The author-state root commits every author's state (open at a frontier entry
//! `{seq, tip_header_hash}`, or closed at a cutoff). The root fields are opaque
//! 32-byte digests here: building them is persistence code's job, not this
//! module's.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::codec::{put_str, ChangeError, Reader};
use crate::ids::FolderGroupId;
use crate::native_protocol::{check_native_tag, native_domain_tag};

/// Domain tag for a [`NativeCheckpoint`]'s canonical encoding. Trailing byte
/// is the generation; there is no migration ladder.
pub const NATIVE_CHECKPOINT_DOMAIN_TAG: &[u8; 8] = &native_domain_tag(b"YLNKnck");

/// SHA-256 of a [`NativeCheckpoint`]'s canonical encoding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeCheckpointHash(pub [u8; 32]);

impl NativeCheckpointHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for NativeCheckpointHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NativeCheckpointHash({})", hex::encode(self.0))
    }
}

/// The root over every author's state (open at an entry, or closed) that a
/// checkpoint commits: [`crate::native_frontier::author_state_root`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorStateRoot(pub [u8; 32]);

impl std::fmt::Debug for AuthorStateRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthorStateRoot({})", hex::encode(self.0))
    }
}

/// The root of the authenticated namespace this checkpoint commits (the
/// `namespace_root`). Opaque here for the same reason as
/// [`AuthorStateRoot`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamespaceRoot(pub [u8; 32]);

impl std::fmt::Debug for NamespaceRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NamespaceRoot({})", hex::encode(self.0))
    }
}

/// A sealer's signed commitment to a group's state at one point: `group`,
/// `namespace_root` and `author_state_root`, plus the sealer's signature over
/// all three.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeCheckpoint {
    pub group_id: FolderGroupId,
    pub namespace_root: NamespaceRoot,
    pub author_state_root: AuthorStateRoot,
    /// Ed25519 by the sealing writer's device key over
    /// [`Self::canonical_encoding`] with the signature field zeroed.
    pub signature: [u8; 64],
}

impl NativeCheckpoint {
    /// Builds an unsigned checkpoint; call [`Self::sign`] before it is trusted
    /// by anything.
    pub fn new(
        group_id: FolderGroupId,
        namespace_root: NamespaceRoot,
        author_state_root: AuthorStateRoot,
    ) -> Self {
        Self { group_id, namespace_root, author_state_root, signature: [0u8; 64] }
    }

    /// The encoding the sealer signs and the encoding this checkpoint's
    /// identity hashes — the signature field itself is excluded, so signing
    /// and hashing are stable regardless of whether `signature` is zeroed
    /// or populated yet.
    fn signed_fields_encoding(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(NATIVE_CHECKPOINT_DOMAIN_TAG);
        put_str(&mut buf, self.group_id.as_str());
        buf.extend_from_slice(&self.namespace_root.0);
        buf.extend_from_slice(&self.author_state_root.0);
        buf
    }

    pub fn checkpoint_hash(&self) -> NativeCheckpointHash {
        NativeCheckpointHash(Sha256::digest(self.signed_fields_encoding()).into())
    }

    /// Signs the checkpoint, overwriting `signature`.
    pub fn sign(&mut self, sealer_key: &SigningKey) {
        let sig = sealer_key.sign(&self.signed_fields_encoding());
        self.signature = sig.to_bytes();
    }

    /// Verifies the signature against a sealer's public key. Callers must
    /// separately confirm that key was a writer's for this group at the policy
    /// point the seal names — that is an
    /// authorization-layer check (mirroring
    /// `authorization_checkpoint.rs`), not this method's job.
    pub fn verify_signature(&self, sealer_public_key: &VerifyingKey) -> Result<(), ChangeError> {
        let sig = Signature::from_bytes(&self.signature);
        sealer_public_key
            .verify(&self.signed_fields_encoding(), &sig)
            .map_err(|_| ChangeError::BadSignature)
    }

    /// Full wire bytes: the signed fields followed by the signature.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = self.signed_fields_encoding();
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut r = Reader::new(bytes);
        check_native_tag(r.take(8)?, NATIVE_CHECKPOINT_DOMAIN_TAG, "native checkpoint")?;
        let group_id = FolderGroupId(r.string()?);
        let namespace_root = NamespaceRoot(r.array32()?);
        let author_state_root = AuthorStateRoot(r.array32()?);
        let signature: [u8; 64] = r
            .take(64)?
            .try_into()
            .map_err(|_| ChangeError::Encoding("signature must be 64 bytes".into()))?;
        r.expect_end()?;
        Ok(Self { group_id, namespace_root, author_state_root, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_protocol::NATIVE_PROTOCOL_GENERATION;

    fn sealer_key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn sample() -> NativeCheckpoint {
        let mut checkpoint = NativeCheckpoint::new(
            FolderGroupId("g1".into()),
            NamespaceRoot([1u8; 32]),
            AuthorStateRoot([2u8; 32]),
        );
        checkpoint.sign(&sealer_key());
        checkpoint
    }

    #[test]
    fn wire_round_trips() {
        let checkpoint = sample();
        let bytes = checkpoint.to_wire_bytes();
        let decoded = NativeCheckpoint::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, checkpoint);
        assert_eq!(decoded.checkpoint_hash(), checkpoint.checkpoint_hash());
    }

    #[test]
    fn signature_verifies_against_the_sealer_key() {
        let checkpoint = sample();
        checkpoint.verify_signature(&sealer_key().verifying_key()).unwrap();
    }

    #[test]
    fn wrong_key_fails_signature_verification() {
        let checkpoint = sample();
        let other_key = SigningKey::from_bytes(&[4u8; 32]).verifying_key();
        assert_eq!(checkpoint.verify_signature(&other_key), Err(ChangeError::BadSignature));
    }

    #[test]
    fn hash_is_stable_regardless_of_signature_presence() {
        let mut unsigned = NativeCheckpoint::new(
            FolderGroupId("g1".into()),
            NamespaceRoot([1u8; 32]),
            AuthorStateRoot([2u8; 32]),
        );
        let unsigned_hash = unsigned.checkpoint_hash();
        unsigned.sign(&sealer_key());
        assert_eq!(unsigned.checkpoint_hash(), unsigned_hash);
    }

    #[test]
    fn foreign_generation_tag_is_refused() {
        let checkpoint = sample();
        let mut bytes = checkpoint.to_wire_bytes();
        bytes[7] = 0xff;
        let err = NativeCheckpoint::from_wire_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            ChangeError::UnsupportedGeneration { theirs: 0xff, ours: NATIVE_PROTOCOL_GENERATION }
        );
    }

    #[test]
    fn the_previous_generation_is_refused() {
        let mut bytes = sample().to_wire_bytes();
        bytes[7] = NATIVE_PROTOCOL_GENERATION - 1;
        assert_eq!(
            NativeCheckpoint::from_wire_bytes(&bytes).unwrap_err(),
            ChangeError::UnsupportedGeneration {
                theirs: NATIVE_PROTOCOL_GENERATION - 1,
                ours: NATIVE_PROTOCOL_GENERATION
            }
        );
    }

    /// The identity of one fixed checkpoint, byte for byte: changing the
    /// signed fields or their order without a new generation tag fails this.
    #[test]
    fn the_hash_of_a_fixed_checkpoint_is_pinned_to_its_generation() {
        assert_eq!(&NATIVE_CHECKPOINT_DOMAIN_TAG[..7], b"YLNKnck");
        assert_eq!(NATIVE_CHECKPOINT_DOMAIN_TAG[7], NATIVE_PROTOCOL_GENERATION);
        assert_eq!(
            hex::encode(sample().checkpoint_hash().0),
            "499a8b54f800e647710c14177de1f92432df0429c7ba028b5569f37421a05e29"
        );
    }
}
