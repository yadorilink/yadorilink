//! Authorization that a writer sealed one specific
//! [`NativeCheckpoint`], verified over the
//! authority/authorization layer (`authorization_checkpoint`'s
//! `AuthorizationCheckpoint`/`MerkleProof`/`verify_change_admission`). It
//! does not reimplement or reinterpret any of that layer's rules; it only
//! computes a domain-separated leaf identifying *this* checkpoint and hands
//! the same `verify_change_admission` primitive that leaf in place of a
//! change/delta hash:
//!
//! ```text
//! authority / authorization layer (authorization_checkpoint.rs)
//!         |
//!    verify_native_checkpoint_seal_...   -- proves a NativeCheckpoint seal
//! ```
//!
//! Authorized writers are trusted for truthful state observation and
//! completeness, so sealing is writer authority: no quorum is required, and
//! multiple writers may seal concurrently. A device that is a writer under the
//! checkpoint's key at the policy point may seal and a viewer may not -- there
//! is no separate grant/revoke machinery for it, and none is being added here
//! (no threshold/quorum scheme; see [`NativeSealPolicy`]).
//!
//! This is a distinct authorized object from the per-delta publish-time
//! authorization (`proof_carrying_delta::verify_proof_carrying_delta`): a
//! `NativeCheckpoint` (a sealer's periodic summary) is not a `NativeDelta`
//! (one author's edit), and the two must never be conflated even though
//! both are verified through the one shared primitive.

use ed25519_dalek::VerifyingKey;

use crate::authorization_checkpoint::{
    canonical_signing_bytes, decode_checkpoint, decode_merkle_proof, encode_merkle_proof,
    verify_change_admission, AuthorizationCheckpoint, CheckpointAdmissionError, MerkleProof,
};
use crate::ids::DeviceId;
use crate::native_checkpoint::NativeCheckpoint;
use crate::native_protocol::{native_domain_tag, NATIVE_TAG_PREFIX_LEN};
use sha2::{Digest, Sha256};

/// Domain tag for [`native_checkpoint_seal_leaf`]'s hash. Distinct from
/// every other leaf/change/delta tag in the crate, so a native-checkpoint
/// seal leaf is never confused with any of them.
pub const NATIVE_CHECKPOINT_SEAL_LEAF_TAG: &[u8; 8] = &native_domain_tag(b"YLNKnsl");

/// Domain tag opening a [`NativeCheckpointSealProof`]'s encoding. Last byte
/// is the encoding generation.
pub const NATIVE_CHECKPOINT_SEAL_PROOF_TAG: &[u8; 8] = &native_domain_tag(b"YLNKnsp");

/// The leaf a native-checkpoint seal authorization's checkpoint covers:
/// SHA-256 of [`NATIVE_CHECKPOINT_SEAL_LEAF_TAG`], the group (length
/// prefixed), and the sealed `NativeCheckpoint`'s own content hash. Binding
/// to the checkpoint's hash (rather than, say, a sealer/round number)
/// means this leaf authorizes exactly one specific sealed summary, never a
/// blanket "this device may seal checkpoints in general."
pub fn native_checkpoint_seal_leaf(group_id: &str, checkpoint: &NativeCheckpoint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NATIVE_CHECKPOINT_SEAL_LEAF_TAG);
    hasher.update((group_id.len() as u64).to_be_bytes());
    hasher.update(group_id.as_bytes());
    hasher.update(checkpoint.checkpoint_hash().0);
    hasher.finalize().into()
}

/// The authority-signed part of a native-checkpoint seal's evidence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeCheckpointSealProof {
    /// The checkpoint the group's authority signed for the sealer.
    pub authority_checkpoint: AuthorizationCheckpoint,
    pub authority_checkpoint_signature: [u8; 64],
    /// The sealer's Ed25519 public key (the same key `NativeCheckpoint`
    /// itself was signed with); the authority checkpoint commits to its
    /// fingerprint.
    pub sealer_public_key: [u8; 32],
    /// The seal leaf's inclusion proof under `authority_checkpoint`'s root.
    pub merkle_proof: MerkleProof,
}

/// Why a [`NativeCheckpointSealProof`]'s bytes did not decode.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeCheckpointSealDecodeError {
    #[error("not a native-checkpoint seal proof")]
    NotAProof,
    #[error("native-checkpoint seal proof of generation {theirs}, this build reads {ours}")]
    UnsupportedGeneration { theirs: u8, ours: u8 },
    #[error("malformed native-checkpoint seal proof: {0}")]
    Malformed(&'static str),
}

impl NativeCheckpointSealProof {
    /// The canonical encoding: the tag, the authority checkpoint's
    /// canonical bytes (u32 BE length prefix), the 64 signature bytes, the
    /// 32 sealer key bytes, then the Merkle proof's canonical bytes (u32 BE
    /// length prefix).
    pub fn encode(&self) -> Vec<u8> {
        let checkpoint = canonical_signing_bytes(&self.authority_checkpoint);
        let proof = encode_merkle_proof(&self.merkle_proof);
        let mut out = Vec::with_capacity(8 + 4 + checkpoint.len() + 64 + 32 + 4 + proof.len());
        out.extend_from_slice(NATIVE_CHECKPOINT_SEAL_PROOF_TAG);
        out.extend_from_slice(&(checkpoint.len() as u32).to_be_bytes());
        out.extend_from_slice(&checkpoint);
        out.extend_from_slice(&self.authority_checkpoint_signature);
        out.extend_from_slice(&self.sealer_public_key);
        out.extend_from_slice(&(proof.len() as u32).to_be_bytes());
        out.extend_from_slice(&proof);
        out
    }

    /// The exact inverse of [`Self::encode`]; anything else, including
    /// trailing bytes, is refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCheckpointSealDecodeError> {
        let mut rest = bytes;
        let tag = take(&mut rest, 8).map_err(|_| NativeCheckpointSealDecodeError::NotAProof)?;
        if tag[..NATIVE_TAG_PREFIX_LEN] != NATIVE_CHECKPOINT_SEAL_PROOF_TAG[..NATIVE_TAG_PREFIX_LEN]
        {
            return Err(NativeCheckpointSealDecodeError::NotAProof);
        }
        if tag[NATIVE_TAG_PREFIX_LEN] != NATIVE_CHECKPOINT_SEAL_PROOF_TAG[NATIVE_TAG_PREFIX_LEN] {
            return Err(NativeCheckpointSealDecodeError::UnsupportedGeneration {
                theirs: tag[NATIVE_TAG_PREFIX_LEN],
                ours: NATIVE_CHECKPOINT_SEAL_PROOF_TAG[NATIVE_TAG_PREFIX_LEN],
            });
        }
        let checkpoint_bytes = take_prefixed(&mut rest)?;
        let authority_checkpoint = decode_checkpoint(checkpoint_bytes)
            .map_err(|_| NativeCheckpointSealDecodeError::Malformed("authority checkpoint"))?;
        let authority_checkpoint_signature: [u8; 64] =
            take(&mut rest, 64)?.try_into().expect("64 bytes");
        let sealer_public_key: [u8; 32] = take(&mut rest, 32)?.try_into().expect("32 bytes");
        let merkle_proof = decode_merkle_proof(take_prefixed(&mut rest)?)
            .map_err(|_| NativeCheckpointSealDecodeError::Malformed("merkle proof"))?;
        if !rest.is_empty() {
            return Err(NativeCheckpointSealDecodeError::Malformed("trailing bytes"));
        }
        Ok(Self {
            authority_checkpoint,
            authority_checkpoint_signature,
            sealer_public_key,
            merkle_proof,
        })
    }

    /// This proof as the evidence of `authority_checkpoint.device_id`'s
    /// seal.
    pub fn into_evidence(self) -> NativeCheckpointSealEvidence {
        NativeCheckpointSealEvidence {
            sealer: DeviceId(self.authority_checkpoint.device_id.clone()),
            evidence: self.encode(),
        }
    }
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], NativeCheckpointSealDecodeError> {
    if rest.len() < n {
        return Err(NativeCheckpointSealDecodeError::Malformed("truncated"));
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn take_prefixed<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], NativeCheckpointSealDecodeError> {
    let len = u32::from_be_bytes(take(rest, 4)?.try_into().expect("4 bytes")) as usize;
    take(rest, len)
}

/// A native-checkpoint seal's wire-carriable evidence: who sealed, and the
/// encoded [`NativeCheckpointSealProof`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeCheckpointSealEvidence {
    pub sealer: DeviceId,
    pub evidence: Vec<u8>,
}

/// The policy point a seal was issued against, as the authority pinned it in
/// the checkpoint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SealPolicyPoint {
    pub epoch: u64,
    pub seq: u64,
    pub head: [u8; 32],
}

/// The verifier's view of a group's signed policy chain. Sealing a checkpoint is
/// a writer's act: a viewer never seals, and the chain must place the sealer as
/// a writer under the checkpoint's key at the point the seal names.
pub trait NativeSealPolicy {
    /// The authority key in force at `policy_head`, if its fingerprint is
    /// `signer_key_id`.
    fn resolve_authority_key(
        &self,
        signer_key_id: &[u8; 32],
        policy_head: &[u8; 32],
    ) -> Option<VerifyingKey>;

    /// Whether the verified policy chain vouches for a publication checkpoint
    /// pinned at `point`: it holds exactly `point.head` at `point.seq`, and
    /// `device`, signing under the key whose fingerprint is
    /// `signing_key_fingerprint`, was a writer there. The authority's
    /// signature alone does not establish this.
    fn writer_at_policy_point(
        &self,
        device: &str,
        signing_key_fingerprint: &[u8; 32],
        point: &SealPolicyPoint,
    ) -> bool;
}

/// Why a [`NativeCheckpointSealEvidence`] did not authorize sealing its
/// checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeCheckpointSealRefusal {
    /// The evidence does not decode, or its checkpoint does not name the
    /// expected group/sealer, or its Merkle proof does not cover this
    /// exact checkpoint's leaf.
    EvidenceMissing,
    /// The authority's checkpoint is real and covers this checkpoint's
    /// leaf, but the resolved policy chain does not make the sealer a writer
    /// at the pinned policy point (never granted, revoked by then, or signed
    /// under a key the checkpoint does not commit to).
    SignerNotAuthorized { sealer: DeviceId },
}

/// A native-checkpoint seal authorization that verified.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifiedNativeCheckpointSeal {
    pub sealer: DeviceId,
    pub sealer_public_key: [u8; 32],
    pub policy_point: SealPolicyPoint,
}

/// Verifies that `evidence` authorizes sealing `checkpoint` for `group_id`
/// (module doc). Does not check `checkpoint`'s own sealer signature (that
/// is `NativeCheckpoint::verify_signature`'s job, against
/// `evidence`'s carried `sealer_public_key` -- see this function's doc on
/// call order); this function only establishes that the sealer key was a
/// writer at the policy chain's own pinned point.
pub fn verify_native_checkpoint_seal_authorization(
    group_id: &str,
    checkpoint: &NativeCheckpoint,
    evidence: &NativeCheckpointSealEvidence,
    policy: &dyn NativeSealPolicy,
) -> Result<VerifiedNativeCheckpointSeal, NativeCheckpointSealRefusal> {
    let not_authorized =
        || NativeCheckpointSealRefusal::SignerNotAuthorized { sealer: evidence.sealer.clone() };
    let proof = NativeCheckpointSealProof::decode(&evidence.evidence)
        .map_err(|_| NativeCheckpointSealRefusal::EvidenceMissing)?;
    let sealer_key =
        VerifyingKey::from_bytes(&proof.sealer_public_key).map_err(|_| not_authorized())?;
    let leaf = native_checkpoint_seal_leaf(group_id, checkpoint);
    verify_change_admission(
        group_id,
        evidence.sealer.0.as_str(),
        &sealer_key,
        leaf,
        &proof.merkle_proof,
        &proof.authority_checkpoint,
        &proof.authority_checkpoint_signature,
        |key_id, head| policy.resolve_authority_key(key_id, head),
    )
    .map_err(|error| match error {
        CheckpointAdmissionError::UnknownOrInvalidSignerKey
        | CheckpointAdmissionError::BadCheckpointSignature
        | CheckpointAdmissionError::DeviceMismatch
        | CheckpointAdmissionError::SigningKeyFingerprintMismatch => not_authorized(),
        CheckpointAdmissionError::GroupMismatch
        | CheckpointAdmissionError::LeafCountMismatch
        | CheckpointAdmissionError::LeafIndexOutOfRange
        | CheckpointAdmissionError::ProofDepthMismatch
        | CheckpointAdmissionError::MerkleProofDoesNotMatchCheckpoint => {
            NativeCheckpointSealRefusal::EvidenceMissing
        }
    })?;
    let authority_checkpoint = &proof.authority_checkpoint;
    let policy_point = SealPolicyPoint {
        epoch: authority_checkpoint.policy_epoch,
        seq: authority_checkpoint.policy_seq,
        head: authority_checkpoint.policy_head,
    };
    if !policy.writer_at_policy_point(
        evidence.sealer.0.as_str(),
        &authority_checkpoint.signing_key_fingerprint,
        &policy_point,
    ) {
        return Err(not_authorized());
    }
    Ok(VerifiedNativeCheckpointSeal {
        sealer: evidence.sealer.clone(),
        sealer_public_key: proof.sealer_public_key,
        policy_point,
    })
}

#[cfg(test)]
mod tests;
