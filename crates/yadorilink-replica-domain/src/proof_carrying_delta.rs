//! The single verification of a proof-carrying `NativeDelta`, over the authority/authorization layer
//! (`authorization_checkpoint`'s
//! `AuthorizationCheckpoint`/`MerkleProof`/`verify_change_admission`). It
//! does not reimplement or reinterpret any of that layer's rules; it only
//! decodes and self-consistency-checks a `NativeDelta`, then hands the
//! `verify_change_admission` primitive the delta's own [`DeltaHash`]:
//!
//! ```text
//! authority / authorization layer (authorization_checkpoint.rs)
//!         |
//!    verify_proof_carrying_delta   -- proves a NativeDelta's publication
//! ```
//!
//! A proof-carrying delta is self-contained: everything needed to decide
//! whether it may be admitted travels with it. Verification is exactly one
//! function, called by every receive path, rather than assembled
//! separately at each one.

use ed25519_dalek::VerifyingKey;

use crate::authorization_checkpoint::{
    checkpoint_hash as compute_checkpoint_hash, decode_checkpoint, verify_change_admission,
    AuthorizationCheckpoint, CheckpointAdmissionError, CheckpointDecodeError, MerkleProof,
};
use crate::codec::ChangeError;
use crate::signed_delta::NativeDelta;

/// Everything a receiver needs to verify one `NativeDelta` offline.
#[derive(Clone, Copy, Debug)]
pub struct ProofCarryingDelta<'a> {
    pub encoded_delta: &'a [u8],
    pub checkpoint_hash: &'a [u8; 32],
    pub checkpoint_encoded: &'a [u8],
    pub checkpoint_signature: &'a [u8; 64],
    pub author_signing_public_key: &'a [u8; 32],
    pub proof: &'a MerkleProof,
}

/// What verification established.
#[derive(Clone, Debug)]
pub struct VerifiedDelta {
    pub delta: NativeDelta,
    pub delta_hash: crate::native_state::DeltaHash,
    pub checkpoint: AuthorizationCheckpoint,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeltaProofVerificationError {
    UndecodableDelta(ChangeError),
    GroupMismatch { expected: String, actual: String },
    NonCanonicalEncoding,
    CheckpointHashMismatch,
    UndecodableCheckpoint(CheckpointDecodeError),
    CheckpointGroupMismatch { delta: String, checkpoint: String },
    CheckpointDeviceMismatch { delta: String, checkpoint: String },
    MalformedAuthorKey,
    BadDeltaSignature(ChangeError),
    NotAdmissible(CheckpointAdmissionError),
}

impl std::fmt::Display for DeltaProofVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UndecodableDelta(error) => write!(f, "delta does not decode: {error}"),
            Self::GroupMismatch { expected, actual } => {
                write!(f, "delta is bound to group {actual}, expected {expected}")
            }
            Self::NonCanonicalEncoding => {
                f.write_str("the carried bytes are not the delta's canonical encoding")
            }
            Self::CheckpointHashMismatch => {
                f.write_str("checkpoint envelope does not match the claimed checkpoint hash")
            }
            Self::UndecodableCheckpoint(error) => {
                write!(f, "checkpoint does not decode: {error:?}")
            }
            Self::CheckpointGroupMismatch { delta, checkpoint } => {
                write!(f, "checkpoint is bound to group {checkpoint} but the delta to {delta}")
            }
            Self::CheckpointDeviceMismatch { delta, checkpoint } => write!(
                f,
                "checkpoint is for device {checkpoint} but the delta was authored by {delta}"
            ),
            Self::MalformedAuthorKey => f.write_str("author signing key is not a valid public key"),
            Self::BadDeltaSignature(error) => {
                write!(f, "the delta's own signature does not verify: {error}")
            }
            Self::NotAdmissible(error) => {
                write!(f, "the delta is not admissible under its checkpoint: {error:?}")
            }
        }
    }
}

impl std::error::Error for DeltaProofVerificationError {}

/// Verify a proof-carrying `NativeDelta` in full. The step order
/// matters: each check relies on the ones before it. `checkpoint.device_id`
/// is compared against the delta's `author.device`, since the
/// checkpoint authorizes a DEVICE's publication, not an incarnation, and a
/// device's incarnation change does not by itself require a new checkpoint.
pub fn verify_proof_carrying_delta(
    input: &ProofCarryingDelta<'_>,
    expected_group_id: &str,
    resolve_authority_key: impl FnOnce(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey>,
) -> Result<VerifiedDelta, DeltaProofVerificationError> {
    let delta = NativeDelta::from_wire_bytes(input.encoded_delta)
        .map_err(DeltaProofVerificationError::UndecodableDelta)?;

    if delta.group_id.as_str() != expected_group_id {
        return Err(DeltaProofVerificationError::GroupMismatch {
            expected: expected_group_id.to_owned(),
            actual: delta.group_id.as_str().to_owned(),
        });
    }

    if delta.to_wire_bytes() != input.encoded_delta {
        return Err(DeltaProofVerificationError::NonCanonicalEncoding);
    }

    if compute_checkpoint_hash(input.checkpoint_encoded, input.checkpoint_signature)
        != *input.checkpoint_hash
    {
        return Err(DeltaProofVerificationError::CheckpointHashMismatch);
    }

    let checkpoint = decode_checkpoint(input.checkpoint_encoded)
        .map_err(DeltaProofVerificationError::UndecodableCheckpoint)?;

    if checkpoint.group_id != delta.group_id.as_str() {
        return Err(DeltaProofVerificationError::CheckpointGroupMismatch {
            delta: delta.group_id.as_str().to_owned(),
            checkpoint: checkpoint.group_id,
        });
    }
    if checkpoint.device_id != delta.author.device.as_str() {
        return Err(DeltaProofVerificationError::CheckpointDeviceMismatch {
            delta: delta.author.device.as_str().to_owned(),
            checkpoint: checkpoint.device_id,
        });
    }

    let author_key = VerifyingKey::from_bytes(input.author_signing_public_key)
        .map_err(|_| DeltaProofVerificationError::MalformedAuthorKey)?;

    delta.verify_signature(&author_key).map_err(DeltaProofVerificationError::BadDeltaSignature)?;

    let delta_hash = delta.delta_hash();
    verify_change_admission(
        expected_group_id,
        delta.author.device.as_str(),
        &author_key,
        delta_hash.0,
        input.proof,
        &checkpoint,
        input.checkpoint_signature,
        resolve_authority_key,
    )
    .map_err(DeltaProofVerificationError::NotAdmissible)?;

    Ok(VerifiedDelta { delta, delta_hash, checkpoint })
}

#[cfg(test)]
mod tests;
