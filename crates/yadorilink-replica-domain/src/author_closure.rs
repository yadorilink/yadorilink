//! The closure of an author-incarnation, signed by the closed device itself.
//!
//! An incarnation is closed only by its own device: the closure names the
//! group, the author (device and incarnation) and the cutoff, the position of
//! the author's last admissible delta (`None`: closed before the first delta).
//! The device signs `CLOSURE_DOMAIN_TAG || group || author || cutoff` with the
//! key it signs deltas with, and the closure carries that public key together
//! with the publication-time authorization that vouches for it (an authority
//! signed checkpoint naming the device and the key fingerprint), so a receiver
//! judges the key the way it judges a delta's: a later revocation does not
//! invalidate a closure signed before it.
//!
//! A closure is not a delta: it has no sequence and extends no chain.
//!
//! ```text
//! wire = signed content | author public key[32] | signature[64] | authorization
//! signed content = CLOSURE_DOMAIN_TAG | group | author | cutoff
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::author::AuthorId;
use crate::authorization_checkpoint::{
    decode_checkpoint, verify_checkpoint_authorization, AuthorizationCheckpoint,
    CheckpointAdmissionError,
};
use crate::codec::{put_len_bytes, put_str, put_u64, ChangeError, Reader};
use crate::ids::{AuthorSeq, FolderGroupId};
use crate::native_frontier::NativeAuthorFrontierEntry;
use crate::native_protocol::{check_native_tag, native_domain_tag};
use crate::native_state::DeltaHash;

/// Domain tag of a closure's signed content and wire encoding.
pub const CLOSURE_DOMAIN_TAG: &[u8; 8] = &native_domain_tag(b"YLNKacl");

/// A closure before it is signed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthorClosure {
    pub group_id: FolderGroupId,
    pub author: AuthorId,
    /// The author's last admissible position; `None` closes it before its first delta.
    pub cutoff: Option<NativeAuthorFrontierEntry>,
}

/// How two cutoffs of one author relate. `None` is the lowest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClosureJoin {
    /// The first cutoff is strictly lower: it wins.
    Lower,
    /// The first cutoff is strictly higher: the other wins.
    Higher,
    /// The same sequence and the same tip.
    Identical,
    /// The same sequence with different tips: two valid signatures of one
    /// author cut its chain differently. Never resolved by picking one.
    Fork,
}

/// Compares two cutoffs of one author: lower sequence wins, equal sequences
/// must have equal tips.
pub fn join_cutoffs(
    a: Option<&NativeAuthorFrontierEntry>,
    b: Option<&NativeAuthorFrontierEntry>,
) -> ClosureJoin {
    match (a, b) {
        (None, None) => ClosureJoin::Identical,
        (None, Some(_)) => ClosureJoin::Lower,
        (Some(_), None) => ClosureJoin::Higher,
        (Some(a), Some(b)) => match a.seq.cmp(&b.seq) {
            std::cmp::Ordering::Less => ClosureJoin::Lower,
            std::cmp::Ordering::Greater => ClosureJoin::Higher,
            std::cmp::Ordering::Equal if a.tip == b.tip => ClosureJoin::Identical,
            std::cmp::Ordering::Equal => ClosureJoin::Fork,
        },
    }
}

impl AuthorClosure {
    /// The bytes the closed device signs, and the head of the wire encoding.
    pub fn signed_content(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(CLOSURE_DOMAIN_TAG);
        put_str(&mut buf, self.group_id.as_str());
        self.author.encode_into(&mut buf);
        match &self.cutoff {
            None => buf.push(0),
            Some(entry) => {
                buf.push(1);
                put_u64(&mut buf, entry.seq.get());
                buf.extend_from_slice(&entry.tip.0);
            }
        }
        buf
    }

    /// Signs the closure with the closed device's key. `authorization` is the
    /// encoded authority checkpoint and its 64-byte signature that vouch for
    /// the key, or empty when this device holds none.
    pub fn sign(self, key: &SigningKey, authorization: Vec<u8>) -> SignedAuthorClosure {
        let signature = key.sign(&self.signed_content()).to_bytes();
        SignedAuthorClosure {
            closure: self,
            author_public_key: key.verifying_key().to_bytes(),
            signature,
            authorization,
        }
    }
}

/// A closure with its signature, key and authorization.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedAuthorClosure {
    pub closure: AuthorClosure,
    pub author_public_key: [u8; 32],
    pub signature: [u8; 64],
    /// The authority's checkpoint (encoded) followed by its 64-byte signature:
    /// the publication-time authorization of the key. Empty when none is held,
    /// which only a device's own not-yet-exportable closure can be.
    pub authorization: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClosureError {
    GroupMismatch {
        expected: String,
        actual: String,
    },
    MalformedKey,
    BadSignature,
    /// The closure carries no authorization for its key.
    NoAuthorization,
    MalformedAuthorization(String),
    /// The checkpoint does not authorize this device's key for this group. A
    /// closure signed by another device fails here: the checkpoint names the
    /// signer's device, not the closed author's.
    NotAuthorized(CheckpointAdmissionError),
}

impl std::fmt::Display for ClosureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GroupMismatch { expected, actual } => {
                write!(f, "closure is for group {actual}, expected {expected}")
            }
            Self::MalformedKey => f.write_str("closure key is not a valid public key"),
            Self::BadSignature => f.write_str("closure signature does not verify"),
            Self::NoAuthorization => f.write_str("closure carries no authorization"),
            Self::MalformedAuthorization(why) => write!(f, "closure authorization: {why}"),
            Self::NotAuthorized(why) => {
                write!(f, "closure key is not authorized for the closed device: {why:?}")
            }
        }
    }
}

impl std::error::Error for ClosureError {}

impl SignedAuthorClosure {
    /// SHA-256 of the signed content and the signature: the closure's identity.
    pub fn closure_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.closure.signed_content());
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    /// The authority checkpoint and its signature the authorization holds.
    pub fn authorization_parts(&self) -> Result<(AuthorizationCheckpoint, [u8; 64]), ClosureError> {
        if self.authorization.is_empty() {
            return Err(ClosureError::NoAuthorization);
        }
        let split = self.authorization.len().checked_sub(64).ok_or_else(|| {
            ClosureError::MalformedAuthorization("shorter than a signature".into())
        })?;
        let (encoded, signature) = self.authorization.split_at(split);
        let signature: [u8; 64] = signature.try_into().expect("split at len - 64");
        let checkpoint = decode_checkpoint(encoded)
            .map_err(|error| ClosureError::MalformedAuthorization(format!("{error:?}")))?;
        Ok((checkpoint, signature))
    }

    /// Verifies the closure for `expected_group`: the signature under the carried
    /// key, and that an authority checkpoint (resolved through
    /// `resolve_authority_key`) names exactly the closed author's device and
    /// that key. Returns the checkpoint, so the caller can judge the policy
    /// point it was issued at.
    pub fn verify(
        &self,
        expected_group: &str,
        resolve_authority_key: impl FnOnce(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey>,
    ) -> Result<AuthorizationCheckpoint, ClosureError> {
        if self.closure.group_id.as_str() != expected_group {
            return Err(ClosureError::GroupMismatch {
                expected: expected_group.to_owned(),
                actual: self.closure.group_id.as_str().to_owned(),
            });
        }
        let key = VerifyingKey::from_bytes(&self.author_public_key)
            .map_err(|_| ClosureError::MalformedKey)?;
        key.verify(&self.closure.signed_content(), &Signature::from_bytes(&self.signature))
            .map_err(|_| ClosureError::BadSignature)?;
        let (checkpoint, checkpoint_signature) = self.authorization_parts()?;
        verify_checkpoint_authorization(
            expected_group,
            self.closure.author.device.as_str(),
            &key,
            &checkpoint,
            &checkpoint_signature,
            resolve_authority_key,
        )
        .map_err(ClosureError::NotAuthorized)?;
        Ok(checkpoint)
    }

    /// Rebuilds a closure from the pieces a store keeps apart: the signed content
    /// (see [`AuthorClosure::signed_content`]), the key, the signature and the
    /// authorization.
    pub fn from_parts(
        signed_content: &[u8],
        author_public_key: [u8; 32],
        signature: [u8; 64],
        authorization: &[u8],
    ) -> Result<Self, ChangeError> {
        let mut buf = signed_content.to_vec();
        buf.extend_from_slice(&author_public_key);
        buf.extend_from_slice(&signature);
        put_len_bytes(&mut buf, authorization);
        Self::from_wire_bytes(&buf)
    }

    /// Canonical wire bytes.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = self.closure.signed_content();
        buf.extend_from_slice(&self.author_public_key);
        buf.extend_from_slice(&self.signature);
        put_len_bytes(&mut buf, &self.authorization);
        buf
    }

    /// Decodes wire bytes; structure only, the signature is checked by [`Self::verify`].
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut r = Reader::new(bytes);
        check_native_tag(r.take(8)?, CLOSURE_DOMAIN_TAG, "author closure")?;
        let group_id = FolderGroupId(r.string()?);
        let author = crate::signed_delta::decode_author_id(&mut r)?;
        let cutoff = match r.u8()? {
            0 => None,
            1 => {
                let seq = r.u64()?;
                if seq == 0 {
                    return Err(ChangeError::Malformed("closure cutoff sequence is zero".into()));
                }
                Some(NativeAuthorFrontierEntry {
                    seq: AuthorSeq(seq),
                    tip: DeltaHash(r.array32()?),
                })
            }
            other => {
                return Err(ChangeError::Encoding(format!(
                    "closure cutoff flag {other} is unknown"
                )))
            }
        };
        let author_public_key = r.array32()?;
        let signature: [u8; 64] = r
            .take(64)?
            .try_into()
            .map_err(|_| ChangeError::Encoding("signature must be 64 bytes".into()))?;
        let authorization = r.len_bytes()?;
        r.expect_end()?;
        Ok(Self {
            closure: AuthorClosure { group_id, author, cutoff },
            author_public_key,
            signature,
            authorization,
        })
    }
}

#[cfg(test)]
mod tests;
