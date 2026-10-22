//! `AuthorizationEvidence` — the sole publication authority for a
//! `Change`.
//! Pure, dependency-neutral (no storage, no network, no async): this is
//! the ONE canonical Rust implementation of checkpoint construction and
//! verification, used identically by local checkpoint flush (daemon-side
//! authoring), peer receive (verifying a `PublishedChange` carried in a
//! `ChangeBatch`), and tests. Moved
//! here from `yadorilink-daemon` because none of this depends on the
//! daemon's storage or runtime — only `yadorilink_daemon::change_policy`'s
//! `GroupPolicyState::resolve_authority_key` (supplied to
//! [`verify_change_admission`] as a plain closure) ties a verification
//! into one specific device's verified policy chain.
//!
//! - A device can create Changes fully offline, any time. Locally these
//!   are `Pending` — not yet globally admissible, not yet synced to any
//!   other device.
//! - Publishing them requires reconnecting and asking the coordination
//!   plane to sign a Merkle root over a batch of pending Changes. The
//!   authority checks "is this device CURRENTLY a writer" **at that
//!   moment**, live, and only signs if so. If the device was revoked
//!   before asking, the authority refuses, full stop — no window, no
//!   timestamp, nothing for the device to forge.
//! - The resulting [`AuthorizationCheckpoint`] plus a [`MerkleProof`] for
//!   one specific Change, TOGETHER WITH the author's raw Ed25519 public
//!   key, is what any receiver verifies, fully offline, with no live
//!   connection to the authority, no notion of who delivered the bytes,
//!   and — critically — no dependency on the author still being present
//!   in the receiver's live netmap. A fresh device, or one that only
//!   later joins a group, must be able to verify history from an author
//!   who has since been revoked and forgotten; carrying the raw key in
//!   the proof (rather than requiring the verifier to already have it
//!   pinned) is what makes that possible. See [`verify_change_admission`]
//!   for exactly how that raw key is bound to the checkpoint rather than
//!   independently trusted.
//!
//! **This authorizes at PUBLISH time, not at edit time.** A Change made
//! while offline, during a period the author was later revoked and then
//! re-granted before reconnecting, is admissible once checkpointed —
//! `verify_change_admission` has no way to know or care when a Change was
//! authored, only that it is covered by a checkpoint issued while the
//! author was CURRENTLY a writer. This is not a loophole; it is what
//! follows from refusing to trust any self-reported time. User-facing
//! copy must say "offline editing always works; whether an unpublished
//! edit can reach other devices is decided by your CURRENT write
//! permission at publish time" — never "...decided by your permission
//! when you made the edit," which this design does not provide and
//! should not claim to.
//!
//! The crucial structural property: there is no client-supplied timestamp
//! anywhere in [`verify_change_admission`]. The only things trusted are
//! (a) the authority's Ed25519 signature over the checkpoint (verified
//! under the key that was actually the group's authority key AT
//! `policy_head`, resolved through the caller's own verified policy
//! chain), (b) a Merkle inclusion proof binding one Change's hash to the
//! checkpoint's `merkle_root`, with the checkpoint also committing to the
//! batch's exact `leaf_count` so the proof can't be reinterpreted against
//! a differently-shaped batch that happens to hash to the same root, and
//! (c) the carried author public key hashing to the checkpoint's own
//! `signing_key_fingerprint` — the authority signature already commits to
//! that fingerprint, so the raw key itself needs no independent trust, it
//! only needs to match what the authority actually vouched for. A device
//! cannot manufacture a checkpoint covering a Change the authority never
//! saw while it was still a writer, because the device does not hold the
//! authority's signing key. This is what makes "revocation is immediate"
//! true again: immediate for everything not yet checkpointed, at the one
//! moment that actually matters (checkpoint issuance), rather than
//! approximated by a TTL or a relay's serve-time opinion.
//!
//! One Changes-to-Merkle-root batching means the authority signs once per
//! reconnect/flush, not once per Change. The issuance endpoint MUST
//! linearize checkpoint issuance against revocation (a checkpoint and a
//! revoke for the same device never both commit as if the other had not
//! happened); this module cannot enforce that server-side contract, only
//! what an already-issued checkpoint can be trusted to mean.
//! `signer_key_id` binds each checkpoint to the authority key it was
//! signed under, so authority-key rotation stays verifiable.
//!
//! Carrier/transport identity plays no role anywhere in this file: there
//! is no notion of "who delivered this" in any function signature here,
//! by construction — `Accept(change, direct) == Accept(change, relay) ==
//! Accept(change, TURN)` follows directly from that absence.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Distinct from `yadorilink-daemon`'s `change_policy::POLICY_DOMAIN_TAG`
/// (`b"ylpolic1"`), so a signature over one type can never be replayed as
/// a signature over another, even under the same per-group authority key.
const CHECKPOINT_DOMAIN_TAG: &[u8; 8] = b"ylchkpt1";
/// RFC 6962-style domain separation between leaf and interior node
/// hashing, so a leaf hash can never collide with an interior node hash
/// for the same bytes (a second-preimage trick that would otherwise let
/// an attacker pass off a Change hash as a valid subtree, or vice versa).
const MERKLE_LEAF_PREFIX: u8 = 0x00;
const MERKLE_NODE_PREFIX: u8 = 0x01;

/// SHA-256 of a pinned Ed25519 verifying key, in the one encoding every
/// authorization-adjacent fingerprint in this codebase must share
/// (`change_policy::PolicyRecord::signing_key_fingerprint` and this
/// module's own `AuthorizationCheckpoint::signing_key_fingerprint`) —
/// callers must never hand-roll this hash differently in two places.
pub fn fingerprint_signing_key(key: &VerifyingKey) -> [u8; 32] {
    let digest = Sha256::digest(key.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// A batch authorization, signed by whichever key was the group's
/// coordination-plane authority key at `policy_head` (the same chain
/// `change_policy::PolicyRecord`s and `RotateAuthority` records verify
/// against), after checking, live, that `device_id` was a current writer
/// for `group_id` at the moment this was issued. Everything the signature
/// covers is here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCheckpoint {
    pub group_id: String,
    pub device_id: String,
    /// SHA-256 of the device's pinned Ed25519 signing key, matching
    /// `change_policy::PolicyRecord::signing_key_fingerprint`'s encoding.
    pub signing_key_fingerprint: [u8; 32],
    /// Root of a Merkle tree over the Change hashes this checkpoint
    /// covers.
    pub merkle_root: [u8; 32],
    /// Exact number of leaves the tree behind `merkle_root` was built
    /// from. Signed alongside the root so a proof can never be replayed
    /// against a DIFFERENTLY-SHAPED batch that happens to hash to the
    /// same root under this tree's odd-level duplication rule (e.g. a
    /// real 3-leaf batch `[a,b,c]`, padded to `[a,b,c,c]`, produces the
    /// same root as an actual 4-leaf batch `[a,b,c,c]`) — without this
    /// field the checkpoint would not commit to which one it authorized.
    pub leaf_count: u64,
    /// Strictly increasing per (group_id, device_id) — assigned by the
    /// authority, never by the device. Useful for issuance ordering,
    /// retry/idempotency, audit, and duplicate-request detection — NEVER
    /// for deciding an earlier checkpoint is stale or safe to discard. A
    /// checkpoint only ever commits to the specific batch it was signed
    /// over (checkpoint 5 covers exactly the Changes it named, not
    /// "everything up to checkpoint 5"), so a peer holding checkpoint 6
    /// still needs checkpoint 5 to verify a Change that was only ever
    /// covered by it — a higher seq does not supersede a lower one's
    /// evidence. Not itself load-bearing for `verify_change_admission`,
    /// which only cares about Merkle inclusion under the one checkpoint
    /// actually presented.
    pub checkpoint_seq: u64,
    /// Fingerprint (SHA-256 of the public key) of the authority key that
    /// actually produced this checkpoint's signature. Mirrors
    /// `change_policy::PolicyRecord::signer_key_id`'s convention exactly
    /// so a checkpoint fits the SAME rotation history a group's policy
    /// chain already tracks. `verify_change_admission` never trusts a
    /// raw key handed to it directly — it resolves this id against
    /// `policy_head` through the caller's own verified policy chain, so a
    /// checkpoint signed by a key that had already been rotated out by
    /// `policy_head` is rejected the same way a `PolicyRecord` signed by
    /// a stale key would be.
    pub signer_key_id: [u8; 32],
    /// The policy chain point the authority's writer check AND its choice
    /// of signing key were made against.
    pub policy_epoch: u64,
    pub policy_seq: u64,
    pub policy_head: [u8; 32],
    /// When the authority issued this — informational only (diagnostics,
    /// UI "last synced" display). Deliberately NOT part of what
    /// [`verify_change_admission`] checks: this design's whole point is
    /// that no timestamp needs to be trusted for admission to be correct.
    pub issued_at_unix: u64,
}

/// One Change hash's inclusion proof against an [`AuthorizationCheckpoint`]'s
/// `merkle_root` — a standard Merkle audit path (sibling hashes from leaf to
/// root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// 0-indexed position of this leaf among the batch's original Change
    /// hashes, needed to know at each level whether the sibling is the
    /// left or right neighbor.
    pub leaf_index: usize,
    /// Total number of leaves in the tree this proof was built against —
    /// needed to reconstruct the same padding behavior [`merkle_root`]
    /// used for a non-power-of-two batch size, and cross-checked against
    /// [`AuthorizationCheckpoint::leaf_count`] by
    /// [`verify_change_admission`] so a proof can't silently apply to a
    /// batch shape the checkpoint didn't actually commit to.
    pub leaf_count: usize,
    /// Sibling hashes, ordered from the leaf's own level up to the root.
    pub siblings: Vec<[u8; 32]>,
}

/// Plain wire shape for a [`MerkleProof`]: `leaf_index` (u64 BE),
/// `leaf_count` (u64 BE), then each sibling as 32 raw bytes. The ONE
/// canonical encoding, shared by local checkpoint flush (which stores
/// this opaquely in `change_authorization.merkle_proof`) and peer receive
/// (`AuthorizationMerkleProof` in `sync.proto`, decoded via
/// [`decode_merkle_proof`] before being handed to
/// [`verify_change_admission`]).
pub fn encode_merkle_proof(proof: &MerkleProof) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + proof.siblings.len() * 32);
    buf.extend_from_slice(&(proof.leaf_index as u64).to_be_bytes());
    buf.extend_from_slice(&(proof.leaf_count as u64).to_be_bytes());
    for sibling in &proof.siblings {
        buf.extend_from_slice(sibling);
    }
    buf
}

/// The exact inverse of [`encode_merkle_proof`]. `Err` on any malformed
/// shape (wrong total length, a sibling count that doesn't match a whole
/// number of 32-byte chunks) -- never partially decoded.
pub fn decode_merkle_proof(bytes: &[u8]) -> Result<MerkleProof, CheckpointDecodeError> {
    if bytes.len() < 16 {
        return Err(CheckpointDecodeError::Truncated);
    }
    let leaf_index = u64::from_be_bytes(bytes[0..8].try_into().unwrap()) as usize;
    let leaf_count = u64::from_be_bytes(bytes[8..16].try_into().unwrap()) as usize;
    let rest = &bytes[16..];
    if !rest.len().is_multiple_of(32) {
        return Err(CheckpointDecodeError::Truncated);
    }
    let siblings = rest.as_chunks::<32>().0.to_vec();
    Ok(MerkleProof { leaf_index, leaf_count, siblings })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointAdmissionError {
    /// `signer_key_id` does not resolve to any authority key the caller's
    /// verified policy chain recognizes as valid at `policy_head` —
    /// either it was never a valid authority key for this group, or it
    /// had already been rotated out by the time `policy_head` was
    /// reached.
    UnknownOrInvalidSignerKey,
    /// The checkpoint's own signature does not verify under the resolved
    /// authority key — either genuinely forged, or `signer_key_id` names
    /// a real, currently-valid key that is NOT the one that actually
    /// produced this signature.
    BadCheckpointSignature,
    /// The checkpoint is for a different group than the Change claims.
    GroupMismatch,
    /// The checkpoint is for a different device than the Change's author.
    DeviceMismatch,
    /// The carried author public key does not hash to the checkpoint's
    /// own `signing_key_fingerprint` — either the wrong key was carried
    /// alongside this Change, or the device rotated keys after the
    /// checkpoint was issued to the old one.
    SigningKeyFingerprintMismatch,
    /// `proof.leaf_count` does not match `checkpoint.leaf_count` — the
    /// proof was built against a differently-shaped batch than the one
    /// the checkpoint's signature actually commits to.
    LeafCountMismatch,
    /// `proof.leaf_index` is not a valid position in a batch of
    /// `proof.leaf_count` leaves.
    LeafIndexOutOfRange,
    /// The number of sibling hashes in the proof does not match the tree
    /// depth implied by `leaf_count` — a malformed or truncated/extended
    /// proof, rejected before even attempting to recompute a root from it.
    ProofDepthMismatch,
    /// The Merkle proof does not reconstruct the checkpoint's
    /// `merkle_root` — either this Change was never part of the batch
    /// the authority signed, or the proof itself was tampered with. Both
    /// are treated identically: not admitted.
    MerkleProofDoesNotMatchCheckpoint,
}

/// Counts the Merkle leaf and node hashes this thread computes, so a test can
/// assert how a batch operation scales with its size.
#[cfg(any(test, feature = "test-support"))]
pub mod hash_count {
    use std::cell::Cell;

    thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn bump() {
        COUNT.with(|count| count.set(count.get() + 1));
    }

    /// Hashes computed on this thread since the last [`reset`].
    pub fn get() -> u64 {
        COUNT.with(Cell::get)
    }

    pub fn reset() {
        COUNT.with(|count| count.set(0));
    }
}

fn leaf_hash(change_hash: &[u8; 32]) -> [u8; 32] {
    #[cfg(any(test, feature = "test-support"))]
    hash_count::bump();
    let mut hasher = Sha256::new();
    hasher.update([MERKLE_LEAF_PREFIX]);
    hasher.update(change_hash);
    hasher.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    #[cfg(any(test, feature = "test-support"))]
    hash_count::bump();
    let mut hasher = Sha256::new();
    hasher.update([MERKLE_NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Builds a checkpoint's `merkle_root` from a batch's Change hashes, in
/// the exact order the authority will build it — a client-side reference
/// implementation for tests and for the coordination service's own
/// TypeScript mirror (the coordination service),
/// which must reproduce this bit-for-bit or its signed root will never
/// match what a device computes locally. An odd level is completed by
/// duplicating its last node — the common Bitcoin-style convention,
/// documented here so [`build_merkle_proof`] and this function can never
/// silently diverge on padding. The resulting ambiguity (a real batch and
/// its own padding can collide with a different, larger batch's root) is
/// why [`AuthorizationCheckpoint`] separately commits to `leaf_count` —
/// this function alone is not a unique commitment to a batch's contents.
pub fn merkle_root(change_hashes: &[[u8; 32]]) -> [u8; 32] {
    assert!(!change_hashes.is_empty(), "a checkpoint must cover at least one Change");
    let mut level: Vec<[u8; 32]> = change_hashes.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level.chunks(2).map(|pair| node_hash(&pair[0], &pair[1])).collect();
    }
    level[0]
}

/// Number of levels [`merkle_root`]/[`build_merkle_proof`]'s loop climbs
/// for a tree of `leaf_count` leaves — i.e. the number of sibling hashes
/// a well-formed [`MerkleProof`] for that batch size must carry. Computed
/// structurally (no hashing), purely from the count, so
/// `verify_change_admission` can reject a wrong-length proof before
/// touching any hash.
fn expected_proof_depth(leaf_count: usize) -> usize {
    let mut level_len = leaf_count;
    let mut depth = 0;
    while level_len > 1 {
        if level_len % 2 == 1 {
            level_len += 1;
        }
        level_len /= 2;
        depth += 1;
    }
    depth
}

/// Builds the audit path for `change_hashes[leaf_index]`, matching
/// [`merkle_root`]'s tree shape exactly (including the odd-level
/// duplication rule). Hashes the whole tree, so a caller that needs the
/// path of many leaves of one batch uses [`build_merkle_proofs`] instead.
pub fn build_merkle_proof(change_hashes: &[[u8; 32]], leaf_index: usize) -> MerkleProof {
    assert!(leaf_index < change_hashes.len());
    let mut level: Vec<[u8; 32]> = change_hashes.iter().map(leaf_hash).collect();
    let mut index = leaf_index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        let sibling_index = if index.is_multiple_of(2) { index + 1 } else { index - 1 };
        siblings.push(level[sibling_index]);
        level = level.chunks(2).map(|pair| node_hash(&pair[0], &pair[1])).collect();
        index /= 2;
    }
    MerkleProof { leaf_index, leaf_count: change_hashes.len(), siblings }
}

/// The audit path of every leaf of one batch, in leaf order:
/// `build_merkle_proofs(h)[i] == build_merkle_proof(h, i)`. Each tree level is
/// hashed once, so the whole batch costs one hash per tree node rather than a
/// whole tree per leaf.
pub fn build_merkle_proofs(change_hashes: &[[u8; 32]]) -> Vec<MerkleProof> {
    let leaf_count = change_hashes.len();
    let mut proofs: Vec<MerkleProof> = (0..leaf_count)
        .map(|leaf_index| MerkleProof {
            leaf_index,
            leaf_count,
            siblings: Vec::with_capacity(expected_proof_depth(leaf_count)),
        })
        .collect();
    let mut level: Vec<[u8; 32]> = change_hashes.iter().map(leaf_hash).collect();
    // `index` of leaf `i` at the current level is `i >> depth`.
    let mut depth = 0;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        for (leaf, proof) in proofs.iter_mut().enumerate() {
            let index = leaf >> depth;
            let sibling_index = if index.is_multiple_of(2) { index + 1 } else { index - 1 };
            proof.siblings.push(level[sibling_index]);
        }
        level = level.chunks(2).map(|pair| node_hash(&pair[0], &pair[1])).collect();
        depth += 1;
    }
    proofs
}

fn recompute_root_from_proof(change_hash: &[u8; 32], proof: &MerkleProof) -> [u8; 32] {
    let mut hash = leaf_hash(change_hash);
    let mut index = proof.leaf_index;
    for sibling in &proof.siblings {
        hash = if index.is_multiple_of(2) {
            node_hash(&hash, sibling)
        } else {
            node_hash(sibling, &hash)
        };
        index /= 2;
    }
    hash
}

fn write_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// The exact preimage an [`AuthorizationCheckpoint`]'s signature covers.
/// A real cross-implementation contract — see
/// the coordination service,
/// which must reproduce this bit-for-bit, and
/// `change_policy.rs::ACTION_GRANT_WITH_ROLE`'s doc comment for why this
/// kind of preimage shape must never change silently once anything has
/// been signed under it.
pub fn canonical_signing_bytes(checkpoint: &AuthorizationCheckpoint) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(CHECKPOINT_DOMAIN_TAG);
    write_len_prefixed(&mut buf, checkpoint.group_id.as_bytes());
    write_len_prefixed(&mut buf, checkpoint.device_id.as_bytes());
    buf.extend_from_slice(&checkpoint.signing_key_fingerprint);
    buf.extend_from_slice(&checkpoint.merkle_root);
    buf.extend_from_slice(&checkpoint.leaf_count.to_be_bytes());
    buf.extend_from_slice(&checkpoint.checkpoint_seq.to_be_bytes());
    buf.extend_from_slice(&checkpoint.signer_key_id);
    buf.extend_from_slice(&checkpoint.policy_epoch.to_be_bytes());
    buf.extend_from_slice(&checkpoint.policy_seq.to_be_bytes());
    buf.extend_from_slice(&checkpoint.policy_head);
    buf.extend_from_slice(&checkpoint.issued_at_unix.to_be_bytes());
    buf
}

/// Why [`decode_checkpoint`] rejected a checkpoint's wire bytes -- always a
/// decode-shape failure, never an authorization verdict (that is
/// [`CheckpointAdmissionError`]'s job, applied only after a checkpoint
/// decodes successfully).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointDecodeError {
    /// Fewer bytes than the fixed-width tail requires, or a length prefix
    /// naming more bytes than remain.
    Truncated,
    /// The leading 8 bytes are not [`CHECKPOINT_DOMAIN_TAG`] -- either a
    /// different message type entirely, or a future/incompatible version.
    BadDomainTag,
    /// `group_id`/`device_id` bytes are not valid UTF-8.
    InvalidUtf8,
    /// Bytes remain after every field has been consumed.
    TrailingBytes,
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CheckpointDecodeError> {
        let end = self.pos.checked_add(n).ok_or(CheckpointDecodeError::Truncated)?;
        let slice = self.bytes.get(self.pos..end).ok_or(CheckpointDecodeError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn take_array32(&mut self) -> Result<[u8; 32], CheckpointDecodeError> {
        self.take(32)?.try_into().map_err(|_| CheckpointDecodeError::Truncated)
    }

    fn take_u64(&mut self) -> Result<u64, CheckpointDecodeError> {
        let bytes: [u8; 8] =
            self.take(8)?.try_into().map_err(|_| CheckpointDecodeError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn take_len_prefixed_string(&mut self) -> Result<String, CheckpointDecodeError> {
        let len = self.take_u64()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CheckpointDecodeError::InvalidUtf8)
    }
}

/// The exact inverse of [`canonical_signing_bytes`] -- every field in that
/// function's byte layout is either fixed-width or its own explicit
/// length prefix, so the encoding is fully information-preserving and this
/// round-trips it back into a structured [`AuthorizationCheckpoint`].
/// Needed now that a checkpoint's canonical bytes travel as an opaque
/// `bytes` field on the peer-to-peer wire
/// (`AuthorizationCheckpointEnvelope.checkpoint` in `sync.proto`) rather
/// than only ever being reconstructed field-by-field from a JSON HTTP
/// response, as before this design's peer-receive path existed.
pub fn decode_checkpoint(bytes: &[u8]) -> Result<AuthorizationCheckpoint, CheckpointDecodeError> {
    let mut r = Reader::new(bytes);
    let tag = r.take(8)?;
    if tag != CHECKPOINT_DOMAIN_TAG {
        return Err(CheckpointDecodeError::BadDomainTag);
    }
    let group_id = r.take_len_prefixed_string()?;
    let device_id = r.take_len_prefixed_string()?;
    let signing_key_fingerprint = r.take_array32()?;
    let merkle_root = r.take_array32()?;
    let leaf_count = r.take_u64()?;
    let checkpoint_seq = r.take_u64()?;
    let signer_key_id = r.take_array32()?;
    let policy_epoch = r.take_u64()?;
    let policy_seq = r.take_u64()?;
    let policy_head = r.take_array32()?;
    let issued_at_unix = r.take_u64()?;
    if r.pos != r.bytes.len() {
        return Err(CheckpointDecodeError::TrailingBytes);
    }
    Ok(AuthorizationCheckpoint {
        group_id,
        device_id,
        signing_key_fingerprint,
        merkle_root,
        leaf_count,
        checkpoint_seq,
        signer_key_id,
        policy_epoch,
        policy_seq,
        policy_head,
        issued_at_unix,
    })
}

/// Signs `checkpoint` with `signing_key` — the caller (test code, or the
/// the coordination service's own Web Crypto mirror) is responsible for making
/// sure `checkpoint.signer_key_id` actually names `signing_key` and that
/// `signing_key` is the group's live authority key at `policy_head`. This
/// function itself performs no such check: production code never calls
/// it without having just verified, live, that `checkpoint.device_id` is
/// currently a writer — that check is the ENTIRE security property this
/// design provides and belongs to the authority alone to enforce (the
/// linearization contract governs exactly when that check may happen
/// relative to a concurrent revoke).
pub fn sign_checkpoint(checkpoint: &AuthorizationCheckpoint, signing_key: &SigningKey) -> [u8; 64] {
    signing_key.sign(&canonical_signing_bytes(checkpoint)).to_bytes()
}

/// SHA-256(checkpoint's canonical signing bytes || signature) — the exact
/// content-addressed handle a `ChangeBatch`'s `PublishedChange` entries
/// reference (`checkpoint_hash`) so a batch never repeats a checkpoint's
/// full bytes for every Change it covers. Any receiver recomputes this
/// from the checkpoint+signature it actually received and rejects a
/// mismatch BEFORE decoding the checkpoint any further — see
/// `yadorilink-peer-session`'s receive path.
pub fn checkpoint_hash(checkpoint_encoded: &[u8], signature: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(checkpoint_encoded);
    hasher.update(signature);
    hasher.finalize().into()
}

/// Fully offline verification that `change_hash`, authored by
/// `author_device_id` using `author_signing_public_key`, is admissible
/// for `expected_group_id` — because it is covered by a validly-signed
/// [`AuthorizationCheckpoint`].
///
/// `author_signing_public_key` is the RAW key carried alongside the proof
/// (e.g. in a `ChangeBatch`'s `AuthorizationCheckpointEnvelope`), not a
/// value looked up from the verifier's own local key-pin store — a fresh
/// device that has never seen `author_device_id` in its live netmap must
/// still be able to verify this. That raw key is not independently
/// trusted, though: it is bound to the checkpoint by requiring
/// `fingerprint_signing_key(author_signing_public_key)` to equal
/// `checkpoint.signing_key_fingerprint`, and the checkpoint's own
/// signature (verified below) is what actually vouches for that
/// fingerprint. This function does NOT verify the Change's own signature
/// against `author_signing_public_key` — that is
/// `yadorilink_replica_domain::local_op::Change::verify_signature`'s job;
/// callers must call both, in either order, before treating a
/// remotely-received Change as admissible (see that crate's receive-path
/// caller for the required order and why signature verification and
/// checkpoint/proof verification are kept as two separate, independently
/// testable steps rather than merged into one).
///
/// `resolve_authority_key(signer_key_id, policy_head)` is supplied by the
/// caller, backed by that caller's own already-verified policy chain
/// (`yadorilink_daemon::change_policy::GroupPolicyState`) — it must
/// return the authority key that chain considers valid for
/// `signer_key_id` AT `policy_head`, or `None` if no such binding exists
/// (unknown key, or a key that had already been rotated out by that
/// point). This function never accepts a bare "trust this key" parameter
/// for exactly the reason a `PolicyRecord` signed by a stale authority
/// key is rejected elsewhere in this codebase: which key is currently
/// authoritative is a question only the verified policy chain can answer.
///
/// No parameter here is a timestamp the caller controls and this function
/// trusts, and no parameter here identifies a transport/carrier — this is
/// what makes carrier choice provably irrelevant to acceptance.
// Every parameter is an independent input to the acceptance decision, and
// the doc comment above reasons about each one's presence individually --
// specifically that none of them is a caller-controlled timestamp and none
// identifies a carrier. Bundling them into a struct would hide exactly the
// per-parameter argument that makes carrier choice provably irrelevant.
#[allow(clippy::too_many_arguments)]
pub fn verify_change_admission(
    expected_group_id: &str,
    author_device_id: &str,
    author_signing_public_key: &VerifyingKey,
    change_hash: [u8; 32],
    proof: &MerkleProof,
    checkpoint: &AuthorizationCheckpoint,
    checkpoint_signature: &[u8; 64],
    resolve_authority_key: impl FnOnce(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey>,
) -> Result<(), CheckpointAdmissionError> {
    verify_checkpoint_authorization(
        expected_group_id,
        author_device_id,
        author_signing_public_key,
        checkpoint,
        checkpoint_signature,
        resolve_authority_key,
    )?;
    verify_change_inclusion(change_hash, proof, checkpoint)
}

/// The checks of [`verify_change_admission`] that depend only on the
/// checkpoint, not on which Change it is asked about: the authority's
/// signature (through `resolve_authority_key`), and that the checkpoint names
/// this group, device and signing key. A caller admitting every Change of one
/// batch runs this once, then [`verify_change_inclusion`] per Change.
pub fn verify_checkpoint_authorization(
    expected_group_id: &str,
    author_device_id: &str,
    author_signing_public_key: &VerifyingKey,
    checkpoint: &AuthorizationCheckpoint,
    checkpoint_signature: &[u8; 64],
    resolve_authority_key: impl FnOnce(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey>,
) -> Result<(), CheckpointAdmissionError> {
    let authority_key = resolve_authority_key(&checkpoint.signer_key_id, &checkpoint.policy_head)
        .ok_or(CheckpointAdmissionError::UnknownOrInvalidSignerKey)?;

    let sig = Signature::from_bytes(checkpoint_signature);
    authority_key
        .verify(&canonical_signing_bytes(checkpoint), &sig)
        .map_err(|_| CheckpointAdmissionError::BadCheckpointSignature)?;

    if checkpoint.group_id != expected_group_id {
        return Err(CheckpointAdmissionError::GroupMismatch);
    }
    if checkpoint.device_id != author_device_id {
        return Err(CheckpointAdmissionError::DeviceMismatch);
    }
    if checkpoint.signing_key_fingerprint != fingerprint_signing_key(author_signing_public_key) {
        return Err(CheckpointAdmissionError::SigningKeyFingerprintMismatch);
    }
    Ok(())
}

/// The per-Change half of [`verify_change_admission`]: that `proof` places
/// `change_hash` under the root of `checkpoint`, in a batch of the size the
/// checkpoint committed to. The checkpoint itself must already have passed
/// [`verify_checkpoint_authorization`]. Costs one hash per tree level.
pub fn verify_change_inclusion(
    change_hash: [u8; 32],
    proof: &MerkleProof,
    checkpoint: &AuthorizationCheckpoint,
) -> Result<(), CheckpointAdmissionError> {
    if checkpoint.leaf_count != proof.leaf_count as u64 {
        return Err(CheckpointAdmissionError::LeafCountMismatch);
    }
    if proof.leaf_index >= proof.leaf_count {
        return Err(CheckpointAdmissionError::LeafIndexOutOfRange);
    }
    if proof.siblings.len() != expected_proof_depth(proof.leaf_count) {
        return Err(CheckpointAdmissionError::ProofDepthMismatch);
    }
    if recompute_root_from_proof(&change_hash, proof) != checkpoint.merkle_root {
        return Err(CheckpointAdmissionError::MerkleProofDoesNotMatchCheckpoint);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

/// Models the checkpoint-issuance/revoke race as a pure
/// state machine, independent of the coordination plane's actual
/// language/storage (TypeScript/D1). This is executable evidence for the
/// required contract -- "CheckpointIssue succeeds XOR Revoke precedes it
/// and CheckpointIssue fails" -- rather than a test against production
/// code alone. The coordination service's real issuance endpoint must
/// satisfy the same contract this module proves a naive read-then-write
/// implementation does NOT.
#[cfg(test)]
mod checkpoint_issuance_linearization;
