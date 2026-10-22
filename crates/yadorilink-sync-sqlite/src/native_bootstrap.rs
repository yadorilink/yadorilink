//! Native bootstrap: a complete current native state, checkpointed by a
//! sealer, that a fresh replica verifies and installs on its own.
//!
//! A checkpoint is a bootstrap snapshot, not a compaction: what a
//! new device, a new member or a replica with a lost database installs before
//! it applies the deltas that follow. The payload carries:
//!
//! * the sealer-signed [`NativeCheckpoint`] (namespace root and author-state
//!   root);
//! * every live head as `(path, dot, provenance)`, each with the signed delta
//!   that produced it and that delta's publication evidence. The namespace root
//!   commits only provenance hashes, so it cannot by itself attest a head's
//!   version; the delta does, and the receiver re-derives it from it;
//! * every author's state (open at its frontier entry, or closed at a cutoff) so
//!   later deltas chain onto it;
//! * the content versions, and the projection state (kept copies and stable
//!   names; placements are derived by the receiver, and a reconciliation hold
//!   is never carried). Index rows are not carried: the receiver rebuilds its
//!   own from the heads.
//!
//! The receiver reconstructs the state, recomputes the two roots and refuses
//! the payload unless they equal the checkpoint's. Installation is one
//! transaction (`install_checkpoint` replaces the whole group's state: a rare
//! path, linear in the group, not a per-delta one) and arms every changed path
//! for materialization.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::author_closure::SignedAuthorClosure;
use yadorilink_replica_domain::authorization_checkpoint::decode_merkle_proof;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_checkpoint::NativeCheckpoint;
use yadorilink_replica_domain::native_checkpoint_seal::{
    verify_native_checkpoint_seal_authorization, NativeCheckpointSealEvidence, NativeSealPolicy,
    SealPolicyPoint,
};
use yadorilink_replica_domain::native_frontier::{
    author_state_root, frontier_of_states, AuthorState, NativeAuthorFrontier,
    NativeAuthorFrontierEntry, NativeAuthorStates,
};
use yadorilink_replica_domain::native_state::{DeltaHash, Dot, HeadPayload, NativeState};
use yadorilink_replica_domain::proof_carrying_delta::{
    verify_proof_carrying_delta, ProofCarryingDelta,
};

use crate::error::SyncSqliteError;

/// One live head, named by where it is and which delta wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapHead {
    pub path: SyncPath,
    pub dot: Dot,
    pub provenance: DeltaHash,
}

/// A signed delta and its publication evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapDelta {
    pub delta_wire: Vec<u8>,
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_encoded: Vec<u8>,
    pub checkpoint_signature: Vec<u8>,
    pub author_signing_public_key: [u8; 32],
    pub merkle_proof_encoded: Vec<u8>,
}

/// One author's state in the bundle: open at its frontier entry, or closed at
/// its cutoff (no entry: closed before its first delta).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapAuthorState {
    pub author: AuthorId,
    pub state: AuthorState,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NativeBootstrap {
    pub checkpoint: NativeCheckpoint,
    /// The authority's proof that the sealer was a writer when it sealed this
    /// checkpoint. Absent until the authority has been asked; a payload
    /// without it does not verify.
    pub seal: Option<NativeCheckpointSealEvidence>,
    pub heads: Vec<BootstrapHead>,
    pub deltas: Vec<BootstrapDelta>,
    /// Every author's state, which the checkpoint's author-state root commits.
    /// Verification recomputes the root from these, so a state or cutoff that
    /// differs from the one the sealer signed is refused.
    pub authors: Vec<BootstrapAuthorState>,
    /// The signed closure of every closed author, listed in author order: a
    /// closed state is carried only with the proof that its own device closed
    /// it. Verification requires one for every closed state at exactly its
    /// cutoff, and refuses any other.
    pub closures: Vec<SignedAuthorClosure>,
    pub file_versions: Vec<Vec<u8>>,
}

impl NativeBootstrap {
    /// The author states the payload carries, as one map; an author listed twice
    /// is refused.
    pub fn author_states(&self) -> Result<NativeAuthorStates, &'static str> {
        let mut states = NativeAuthorStates::new();
        for entry in &self.authors {
            if states.insert(entry.author.clone(), entry.state).is_some() {
                return Err("an author appears twice in the bundle");
            }
        }
        Ok(states)
    }
}

/// What a payload proved once verified.
pub struct VerifiedNativeBootstrap {
    state: NativeState,
    frontier: NativeAuthorFrontier,
    payload: NativeBootstrap,
    sealer_public_key: ed25519_dalek::VerifyingKey,
    seal: NativeCheckpointSealEvidence,
    seal_policy_point: SealPolicyPoint,
}

impl VerifiedNativeBootstrap {
    /// The payload that was verified.
    pub(crate) fn payload(&self) -> &NativeBootstrap {
        &self.payload
    }

    /// The parts the install writes.
    pub(crate) fn into_parts(
        self,
    ) -> (
        NativeState,
        NativeAuthorFrontier,
        NativeBootstrap,
        ed25519_dalek::VerifyingKey,
        NativeCheckpointSealEvidence,
    ) {
        (self.state, self.frontier, self.payload, self.sealer_public_key, self.seal)
    }

    /// The hash of the checkpoint this payload installs.
    pub fn checkpoint_hash(&self) -> [u8; 32] {
        self.payload.checkpoint.checkpoint_hash().0
    }

    /// The frontier the payload installs: what the checkpoint covers.
    pub fn frontier(&self) -> &NativeAuthorFrontier {
        &self.frontier
    }

    /// The heads the payload installs.
    pub fn state(&self) -> &NativeState {
        &self.state
    }

    /// The state the payload gives `author`: open at an entry, or closed at its cutoff.
    pub fn author_state(&self, author: &AuthorId) -> Option<AuthorState> {
        self.payload.authors.iter().find(|entry| entry.author == *author).map(|e| e.state)
    }

    /// The policy point the seal was verified at: the sealer was a writer there.
    pub fn seal_policy_point(&self) -> SealPolicyPoint {
        self.seal_policy_point
    }
}

fn corrupt(detail: impl Into<String>) -> SyncSqliteError {
    SyncSqliteError::CorruptState(detail.into())
}

/// Builds the payload for `group_id`'s current native state, signing its
/// checkpoint with `sealer_key`, for a payload that travels over the wire: the
/// receiver rebuilds its own rows from the heads (the changed paths are armed),
/// so carrying them would only spend bytes. Heads, signed deltas, frontier,
/// content versions and projection facts are all there. Fails closed if a delta
/// or evidence a head rests on is no longer held: a bootstrap that cannot prove
/// a head is not a bootstrap.
pub fn build_native_recovery_bundle(
    conn: &Connection,
    group_id: &FolderGroupId,
    sealer_key: &ed25519_dalek::SigningKey,
) -> Result<NativeBootstrap, SyncSqliteError> {
    let checkpoint = crate::native_store::seal_checkpoint(conn, group_id, sealer_key)?;
    let state = crate::native_store::load_state(conn, group_id)?;
    let states = crate::native_store::load_author_states(conn, group_id)?;

    let mut heads = Vec::new();
    let mut deltas: BTreeMap<DeltaHash, BootstrapDelta> = BTreeMap::new();
    for (path, path_heads) in &state.heads {
        for (dot, payload) in path_heads {
            heads.push(BootstrapHead {
                path: path.clone(),
                dot: dot.clone(),
                provenance: payload.provenance,
            });
            if deltas.contains_key(&payload.provenance) {
                continue;
            }
            deltas.insert(payload.provenance, delta_evidence(conn, group_id, &payload.provenance)?);
        }
    }

    let authors = states
        .iter()
        .map(|(author, state)| BootstrapAuthorState { author: author.clone(), state: *state })
        .collect();

    // A closed state travels only with the closure its own device signed, and a
    // closure only if it may leave this device (its replacement checkpoint exists).
    let exportable = crate::native_closure::closures_for_export(conn, group_id)?;
    let mut closures = Vec::new();
    for (author, state) in &states {
        let AuthorState::Closed { frontier } = state else { continue };
        let closure = exportable
            .iter()
            .find(|closure| {
                closure.closure.author == *author && closure.closure.cutoff == *frontier
            })
            .ok_or_else(|| {
                corrupt(format!(
                    "cannot bootstrap group {}: {author:?} is closed but no verified closure of \
                     it may be exported",
                    group_id.as_str()
                ))
            })?;
        closures.push(closure.clone());
    }

    let mut versions: BTreeMap<VersionHash, Vec<u8>> = BTreeMap::new();
    for path_heads in state.heads.values() {
        for payload in path_heads.values() {
            if versions.contains_key(&payload.version) {
                continue;
            }
            let version =
                crate::dag_store::get_file_version(conn, group_id.as_str(), &payload.version)?
                    .ok_or_else(|| {
                        corrupt(format!(
                            "content of live version {} is not held",
                            payload.version.to_hex()
                        ))
                    })?;
            versions.insert(payload.version, version.canonical_encoding());
        }
    }
    Ok(NativeBootstrap {
        checkpoint,
        seal: None,
        heads,
        deltas: deltas.into_values().collect(),
        authors,
        closures,
        file_versions: versions.into_values().collect(),
    })
}

/// Adopts the checkpoint this replica itself just sealed, as a joiner adopts the
/// one in a bundle: the seal authorization is verified under `policy`, then the
/// checkpoint, its evidence and the author states it covers are written as one
/// step. `sealed` is the bundle built when the checkpoint was sealed
/// with the authority's evidence attached; nothing is adopted while the evidence is
/// missing, refused or the write fails. Adopting a checkpoint already held changes
/// nothing.
pub fn adopt_own_seal(
    conn: &Connection,
    group_id: &FolderGroupId,
    sealed: &NativeBootstrap,
    policy: &dyn NativeSealPolicy,
) -> Result<(), SyncSqliteError> {
    let seal = sealed.seal.as_ref().ok_or_else(|| {
        SyncSqliteError::InvalidInput("the sealed checkpoint carries no seal authorization".into())
    })?;
    let states = sealed
        .author_states()
        .map_err(|detail| SyncSqliteError::InvalidInput(detail.to_owned()))?;
    crate::native_checkpoint_authorization::install_authorized_checkpoint(
        conn,
        group_id,
        &sealed.checkpoint,
        seal,
        policy,
        &crate::native_checkpoint_frontier::CheckpointCoverage { states },
    )
}

fn delta_evidence(
    conn: &Connection,
    group_id: &FolderGroupId,
    provenance: &DeltaHash,
) -> Result<BootstrapDelta, SyncSqliteError> {
    let missing = |what: &str| {
        corrupt(format!(
            "cannot bootstrap group {}: the {what} of delta {} is not retained",
            group_id.as_str(),
            hex::encode(provenance.0)
        ))
    };
    let delta_wire = crate::native_store::fetch_delta_body_by_hash(conn, group_id, provenance)?
        .ok_or_else(|| missing("signed delta"))?;
    let (checkpoint_hash, merkle_proof_encoded) =
        crate::native_publication::evidence_for(conn, provenance)?
            .ok_or_else(|| missing("publication evidence"))?;
    let (checkpoint_encoded, checkpoint_signature, author_signing_public_key) =
        crate::native_publication::checkpoint_envelope(conn, &checkpoint_hash)?
            .ok_or_else(|| missing("checkpoint envelope"))?;
    Ok(BootstrapDelta {
        delta_wire,
        checkpoint_hash,
        checkpoint_encoded,
        checkpoint_signature,
        author_signing_public_key,
        merkle_proof_encoded,
    })
}

/// Verifies `payload` for `group_id` and reconstructs what it installs.
///
/// `policy` is the receiver's verified view of the group's policy chain: it
/// resolves a publication checkpoint's signer and says whether the sealer was a
/// writer at the point the seal names. Nothing here trusts the payload: the seal evidence
/// must authorize exactly this checkpoint for this group, the checkpoint must
/// carry that sealer's signature, every head is re-derived from its verified
/// delta, and the reconstructed roots must equal the signed checkpoint's.
pub fn verify_native_bootstrap(
    payload: NativeBootstrap,
    group_id: &FolderGroupId,
    policy: &dyn NativeSealPolicy,
) -> Result<VerifiedNativeBootstrap, SyncSqliteError> {
    let refuse =
        |detail: String| SyncSqliteError::InvalidInput(format!("bootstrap refused: {detail}"));
    let resolve_authority_key =
        |key_id: &[u8; 32], head: &[u8; 32]| policy.resolve_authority_key(key_id, head);
    if payload.checkpoint.group_id != *group_id {
        return Err(refuse("the checkpoint is for another group".into()));
    }
    let seal = payload
        .seal
        .clone()
        .ok_or_else(|| refuse("the checkpoint carries no seal authorization".into()))?;
    let sealed = verify_native_checkpoint_seal_authorization(
        group_id.as_str(),
        &payload.checkpoint,
        &seal,
        policy,
    )
    .map_err(|refusal| refuse(format!("the seal is not authorized: {refusal:?}")))?;
    let sealer_public_key = ed25519_dalek::VerifyingKey::from_bytes(&sealed.sealer_public_key)
        .map_err(|_| refuse("the sealer's key is malformed".into()))?;
    payload.checkpoint.verify_signature(&sealer_public_key).map_err(|_| {
        refuse("the checkpoint's signature does not verify under the sealer's key".into())
    })?;

    // Every delta a head rests on, verified as a received delta is.
    let mut verified: BTreeMap<DeltaHash, yadorilink_replica_domain::signed_delta::NativeDelta> =
        BTreeMap::new();
    for delta in &payload.deltas {
        let signature: [u8; 64] = delta
            .checkpoint_signature
            .as_slice()
            .try_into()
            .map_err(|_| refuse("a checkpoint signature is not 64 bytes".into()))?;
        let proof = decode_merkle_proof(&delta.merkle_proof_encoded)
            .map_err(|error| refuse(format!("a merkle proof does not decode: {error:?}")))?;
        let checked = verify_proof_carrying_delta(
            &ProofCarryingDelta {
                encoded_delta: &delta.delta_wire,
                checkpoint_hash: &delta.checkpoint_hash,
                checkpoint_encoded: &delta.checkpoint_encoded,
                checkpoint_signature: &signature,
                author_signing_public_key: &delta.author_signing_public_key,
                proof: &proof,
            },
            group_id.as_str(),
            resolve_authority_key,
        )
        .map_err(|error| refuse(format!("a delta's publication does not verify: {error:?}")))?;
        let point = yadorilink_replica_domain::native_checkpoint_seal::SealPolicyPoint {
            epoch: checked.checkpoint.policy_epoch,
            seq: checked.checkpoint.policy_seq,
            head: checked.checkpoint.policy_head,
        };
        if !policy.writer_at_policy_point(
            &checked.checkpoint.device_id,
            &checked.checkpoint.signing_key_fingerprint,
            &point,
        ) {
            return Err(refuse(
                "a delta's checkpoint is pinned at a policy point the group's policy does not \
                 vouch for"
                    .into(),
            ));
        }
        verified.insert(checked.delta_hash, checked.delta);
    }

    // Only deltas a live head rests on are carried: any other is evidence for
    // nothing the checkpoint commits to, and joining would store it as history.
    let backing: BTreeSet<DeltaHash> = payload.heads.iter().map(|head| head.provenance).collect();
    if payload.deltas.len() != verified.len() || verified.keys().any(|hash| !backing.contains(hash))
    {
        return Err(refuse("the bundle carries a delta that no live head rests on".into()));
    }

    // The author states, and the context the frontier they hold fixes (an
    // author's context is its frontier position).
    let states = payload.author_states().map_err(|detail| refuse(detail.into()))?;
    verify_bundle_closures(&payload.closures, &states, group_id, policy).map_err(refuse)?;
    let frontier = frontier_of_states(&states);
    let mut state = NativeState::new();
    for (author, entry) in &frontier {
        state.context.insert(author.clone(), entry.seq);
    }

    // Each live head, re-derived from the delta that wrote it.
    for head in &payload.heads {
        let delta = verified
            .get(&head.provenance)
            .ok_or_else(|| refuse(format!("no delta for the head at {:?}", head.path.as_str())))?;
        if delta.dot() != head.dot {
            return Err(refuse(format!(
                "the delta for {:?} is not the head's dot",
                head.path.as_str()
            )));
        }
        let put = delta
            .ops
            .iter()
            .find(|op| op.path == head.path)
            .and_then(|op| op.put.as_ref())
            .ok_or_else(|| {
            refuse(format!("the delta does not put at {:?}", head.path.as_str()))
        })?;
        let heads = state.heads.entry(head.path.clone()).or_default();
        if heads
            .insert(
                head.dot.clone(),
                HeadPayload { version: put.version, provenance: head.provenance },
            )
            .is_some()
        {
            return Err(refuse(format!("a head at {:?} is listed twice", head.path.as_str())));
        }
    }
    state.check_invariants().map_err(|error| refuse(format!("the state is not valid: {error}")))?;

    // The roots the sealer signed.
    let namespace = crate::native_store::namespace_root(&state)?;
    if namespace.0 != payload.checkpoint.namespace_root.0 {
        return Err(refuse("the heads do not build the checkpoint's namespace root".into()));
    }
    if author_state_root(&states) != payload.checkpoint.author_state_root.0 {
        return Err(refuse(
            "the author states do not build the checkpoint's author-state root".into(),
        ));
    }

    // Content: every live version is carried, and every row's version is one
    // the payload holds.
    let carried: BTreeSet<VersionHash> = payload
        .file_versions
        .iter()
        .map(|encoded| {
            FileVersion::from_canonical_encoding(encoded)
                .map(|version| version.version_hash)
                .map_err(|error| refuse(format!("a content version is invalid: {error}")))
        })
        .collect::<Result<_, _>>()?;
    for (path, path_heads) in &state.heads {
        for head in path_heads.values() {
            if !carried.contains(&head.version) {
                return Err(refuse(format!(
                    "the content of a live head at {:?} is missing",
                    path.as_str()
                )));
            }
        }
    }

    Ok(VerifiedNativeBootstrap {
        state,
        frontier,
        payload,
        sealer_public_key,
        seal,
        seal_policy_point: sealed.policy_point,
    })
}

/// The closures of a bundle prove its closed states: every closed author has a
/// closure its own device signed (verified, under a key the authority vouched for)
/// whose strictest cutoff is exactly the state's, and no closure is carried for an
/// author the bundle leaves open. Two closures of one author that cut the chain at
/// one sequence with different tips are a fork, and the bundle is refused.
fn verify_bundle_closures(
    closures: &[SignedAuthorClosure],
    states: &NativeAuthorStates,
    group_id: &FolderGroupId,
    policy: &dyn NativeSealPolicy,
) -> Result<(), String> {
    let mut cutoffs: BTreeMap<&AuthorId, Vec<Option<NativeAuthorFrontierEntry>>> = BTreeMap::new();
    for closure in closures {
        crate::native_closure::verify_closure(group_id, closure, policy)
            .map_err(|error| format!("a closure does not verify: {error}"))?;
        cutoffs.entry(&closure.closure.author).or_default().push(closure.closure.cutoff);
    }
    for (author, state) in states {
        let AuthorState::Closed { frontier } = state else { continue };
        let Some(held) = cutoffs.get(author) else {
            return Err(format!("{author:?} is closed in the bundle with no closure of its own"));
        };
        let strictest = crate::native_closure::strictest(held.iter().copied())
            .expect("an author with closures has a strictest cutoff");
        if strictest.fork {
            return Err(format!("two closures of {author:?} fork at one sequence"));
        }
        if strictest.seq != frontier.map(|entry| entry.seq)
            || strictest.tip != frontier.map(|entry| entry.tip)
        {
            return Err(format!("the closure of {author:?} is not at the cutoff it is closed at"));
        }
    }
    for author in cutoffs.keys() {
        if !states.get(*author).is_some_and(AuthorState::is_closed) {
            return Err(format!(
                "a closure of {author:?} is carried but the bundle leaves it open"
            ));
        }
    }
    Ok(())
}

/// Why `name` cannot be a relative path under a synced folder, if it cannot:
/// empty, absolute, with an empty or dot component, or a path the admission of a
/// delta refuses (reserved or non-portable names).
pub(crate) fn projection_name_refusal(name: &str) -> Option<&'static str> {
    use yadorilink_fs_platform::reserved_namespace::{
        wire_path_admission_refusal, WirePathRefusal,
    };
    if name.is_empty() || name.starts_with('/') || name.contains('\\') || name.contains('\0') {
        return Some("not a relative path");
    }
    if name
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Some("it has an empty or dot component");
    }
    match wire_path_admission_refusal(name)? {
        WirePathRefusal::ReservedNamespace => Some("it is in a reserved namespace"),
        WirePathRefusal::NonPortable => Some("it is not portable"),
    }
}

#[cfg(test)]
mod tests {
    mod checkpoint_frontier;
    mod checkpoint_install;
    mod history_lifecycle_red;
    mod persisted_author_state_tamper;
    mod rebootstrap_crash;
    mod rebootstrap_finish_atomic;
    mod rebootstrap_freeze;
    mod rebootstrap_install;
    mod rebootstrap_items;
    mod rebootstrap_preserve;
    mod rebootstrap_replay;
    mod retirement_cutoff;
    mod self_seal;

    use ed25519_dalek::SigningKey;

    use yadorilink_replica_domain::author::IncarnationId;
    use yadorilink_replica_domain::author_closure::{AuthorClosure, SignedAuthorClosure};
    use yadorilink_replica_domain::authorization_checkpoint::{
        build_merkle_proof, canonical_signing_bytes, checkpoint_hash, encode_merkle_proof,
        fingerprint_signing_key, merkle_root, sign_checkpoint, AuthorizationCheckpoint,
    };
    use yadorilink_replica_domain::file::{FileMeta, RecordKind, VersionBlock};
    use yadorilink_replica_domain::ids::{AuthorSeq, BlockHash, DeviceId};
    use yadorilink_replica_domain::native_checkpoint_seal::NativeSealPolicy;
    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, HeadRef, NativeDelta};

    use super::*;
    use crate::native_admission::NativeAdmission;
    use crate::native_checkpoint_install::{
        install_checkpoint, CheckpointError, InstallKind, InstalledCheckpoint,
    };

    const GROUP: &str = "boot";

    fn group() -> FolderGroupId {
        FolderGroupId(GROUP.into())
    }

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&c).unwrap();
        c
    }

    fn author(name: &str) -> AuthorId {
        AuthorId { device: DeviceId(name.into()), incarnation: IncarnationId([1; 16]) }
    }

    fn device_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn authority_key() -> SigningKey {
        SigningKey::from_bytes(&[200; 32])
    }

    fn sealer_key() -> SigningKey {
        SigningKey::from_bytes(&[201; 32])
    }

    fn version(seed: u8) -> FileVersion {
        FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![seed; 32]), size: 4 }],
            4,
            FileMeta {
                // A multiple of 100 ns, so a file system with coarse timestamps can hold it.
                mtime_unix_nanos: seed as i64 * 1_000,
                unix_mode: Some(0o644),
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        )
    }

    /// The receiver's policy: the authority key signs everything, and every
    /// device is a writer.
    struct Policy;

    impl NativeSealPolicy for Policy {
        fn resolve_authority_key(
            &self,
            key_id: &[u8; 32],
            _head: &[u8; 32],
        ) -> Option<ed25519_dalek::VerifyingKey> {
            (*key_id == fingerprint_signing_key(&authority_key().verifying_key()))
                .then(|| authority_key().verifying_key())
        }

        fn writer_at_policy_point(
            &self,
            _device: &str,
            _signing_key_fingerprint: &[u8; 32],
            _point: &yadorilink_replica_domain::native_checkpoint_seal::SealPolicyPoint,
        ) -> bool {
            true
        }
    }

    /// The payload with the authority's seal authorization attached, as a
    /// sealer's device would obtain it from the plane.
    fn sealed(mut payload: NativeBootstrap) -> NativeBootstrap {
        use yadorilink_replica_domain::native_checkpoint_seal::{
            native_checkpoint_seal_leaf, NativeCheckpointSealProof,
        };
        let leaf = native_checkpoint_seal_leaf(GROUP, &payload.checkpoint);
        let authority_checkpoint = AuthorizationCheckpoint {
            group_id: GROUP.into(),
            device_id: "sealer-device".into(),
            signing_key_fingerprint: fingerprint_signing_key(&sealer_key().verifying_key()),
            merkle_root: merkle_root(&[leaf]),
            leaf_count: 1,
            checkpoint_seq: 1,
            signer_key_id: fingerprint_signing_key(&authority_key().verifying_key()),
            policy_epoch: 0,
            policy_seq: 1,
            policy_head: [0; 32],
            issued_at_unix: 0,
        };
        payload.seal = Some(
            NativeCheckpointSealProof {
                authority_checkpoint_signature: sign_checkpoint(
                    &authority_checkpoint,
                    &authority_key(),
                ),
                authority_checkpoint,
                sealer_public_key: sealer_key().verifying_key().to_bytes(),
                merkle_proof: build_merkle_proof(&[leaf], 0),
            }
            .into_evidence(),
        );
        payload
    }

    fn built(conn: &Connection) -> NativeBootstrap {
        sealed(build_native_recovery_bundle(conn, &group(), &sealer_key()).unwrap())
    }

    /// The test key of `device`: the devices the tests name hold the keys the
    /// seeds below stand for.
    pub(super) fn device_seed(device: &str) -> u8 {
        match device {
            "device-a" => 1,
            "device-b" => 2,
            "device-c" => 3,
            "device-d" => 4,
            "device-s" => 4,
            "sealer-device" => 201,
            other => panic!("no test key for {other}"),
        }
    }

    /// The authority's checkpoint for `device` holding the key of `key_seed`, as
    /// the authorization a closure carries.
    pub(super) fn authorization_of(device: &str, key_seed: u8) -> Vec<u8> {
        let key = device_key(key_seed);
        let checkpoint = AuthorizationCheckpoint {
            group_id: GROUP.into(),
            device_id: device.into(),
            signing_key_fingerprint: fingerprint_signing_key(&key.verifying_key()),
            merkle_root: merkle_root(&[[9; 32]]),
            leaf_count: 1,
            checkpoint_seq: 1,
            signer_key_id: fingerprint_signing_key(&authority_key().verifying_key()),
            policy_epoch: 0,
            policy_seq: 1,
            policy_head: [0; 32],
            issued_at_unix: 0,
        };
        let mut bytes = canonical_signing_bytes(&checkpoint);
        bytes.extend_from_slice(&sign_checkpoint(&checkpoint, &authority_key()));
        bytes
    }

    /// A closure of `who` at `cutoff`, signed with the key of `signer_seed` and
    /// carrying the authorization the authority issued to `auth_device` for the
    /// key of `auth_seed`.
    pub(super) fn closure_signed(
        who: &AuthorId,
        cutoff: Option<NativeAuthorFrontierEntry>,
        signer_seed: u8,
        auth_device: &str,
        auth_seed: u8,
    ) -> SignedAuthorClosure {
        AuthorClosure { group_id: group(), author: who.clone(), cutoff }
            .sign(&device_key(signer_seed), authorization_of(auth_device, auth_seed))
    }

    /// Closes `who` at its current frontier entry (none: before its first delta),
    /// the way a closure that came with a replacement bundle does.
    pub(super) fn close_author(c: &Connection, group: &FolderGroupId, who: &AuthorId) {
        let cutoff = crate::native_store::frontier_entry_get(c, group, who).unwrap();
        let seed = device_seed(who.device.as_str());
        let closure = closure_signed(who, cutoff, seed, who.device.as_str(), seed);
        crate::native_closure::store_bundle_closure(c, group, &closure, [7; 32], &Policy).unwrap();
    }

    /// Closes `who` above `cutoff` on this replica alone, the way a rotation does:
    /// a closure its own device signed that gates admission at once and may not
    /// leave the device yet.
    pub(super) fn rotation_closure_at(
        c: &Connection,
        group: &FolderGroupId,
        who: &AuthorId,
        cutoff: Option<AuthorSeq>,
    ) {
        let entry = cutoff.map(|seq| NativeAuthorFrontierEntry {
            seq,
            tip: crate::native_store::delta_log_hash(c, group, who, seq)
                .unwrap()
                .unwrap_or(DeltaHash([seq.get() as u8; 32])),
        });
        let seed = device_seed(who.device.as_str());
        let closure = closure_signed(who, entry, seed, who.device.as_str(), seed);
        crate::native_closure::record_rotation_closure(c, &closure).unwrap();
    }

    /// The cutoff of the closure `who`'s own device signed that has not left the
    /// device: `Some(cutoff)` while one is held, `None` otherwise.
    pub(super) fn unexported_rotation_cutoff(
        c: &Connection,
        group: &FolderGroupId,
        who: &AuthorId,
    ) -> Option<Option<AuthorSeq>> {
        let mut stmt = c
            .prepare(
                "SELECT cutoff_seq FROM native_author_closure WHERE group_id = ?1 \
                 AND author = ?2 AND incarnation = ?3 AND replacement_checkpoint_hash IS NULL",
            )
            .unwrap();
        let cutoffs: Vec<Option<i64>> = stmt
            .query_map((group.as_str(), who.device.as_str(), who.incarnation.0.as_slice()), |row| {
                row.get(0)
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        cutoffs
            .into_iter()
            .map(|seq| seq.map(|seq| AuthorSeq(seq as u64)))
            .min_by_key(|seq| seq.map_or(0, AuthorSeq::get))
    }

    /// Signs `delta` as `who`, installs it and publishes it under a checkpoint
    /// the authority signed.
    fn publish(c: &Connection, who: &AuthorId, key: &SigningKey, mut delta: NativeDelta) {
        delta.sign(key);
        crate::native_store::install_verified_delta(c, &group(), &delta, &key.verifying_key())
            .unwrap();
        let leaves = [delta.delta_hash().0];
        let checkpoint = AuthorizationCheckpoint {
            group_id: GROUP.into(),
            device_id: who.device.0.clone(),
            signing_key_fingerprint: fingerprint_signing_key(&key.verifying_key()),
            merkle_root: merkle_root(&leaves),
            leaf_count: 1,
            checkpoint_seq: delta.seq.get(),
            signer_key_id: fingerprint_signing_key(&authority_key().verifying_key()),
            policy_epoch: 0,
            policy_seq: 1,
            policy_head: [0; 32],
            issued_at_unix: 0,
        };
        let encoded = canonical_signing_bytes(&checkpoint);
        let signature = sign_checkpoint(&checkpoint, &authority_key());
        crate::native_publication::attach_authorization_evidence(
            c,
            &checkpoint_hash(&encoded, &signature),
            GROUP,
            &who.device.0,
            delta.seq.get(),
            &encoded,
            &signature,
            &key.verifying_key().to_bytes(),
            &[(delta.delta_hash(), encode_merkle_proof(&build_merkle_proof(&leaves, 0)))],
        )
        .unwrap();
    }

    fn put_delta(
        who: &AuthorId,
        seq: u64,
        prev: Option<DeltaHash>,
        path: &str,
        v: u8,
    ) -> NativeDelta {
        NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: who.clone(),
            seq: AuthorSeq(seq),
            prev,
            ops: vec![DeltaOp {
                path: SyncPath(path.into()),
                removes: Vec::new(),
                put: Some(DeltaPut { version: version(v).version_hash }),
            }],
            signature: [0; 64],
        }
    }

    /// Two authors write `x` concurrently, one also writes `y` and removes the
    /// other's `x`, so the frontier has two authors and a removal.
    fn source() -> (Connection, AuthorId, AuthorId) {
        let c = conn();
        for seed in 1..=4 {
            crate::dag_store::put_file_version(&c, GROUP, &version(seed)).unwrap();
        }
        let (a, b) = (author("device-a"), author("device-b"));
        let (ka, kb) = (device_key(1), device_key(2));
        let a1 = put_delta(&a, 1, None, "x", 1);
        let a1_hash = {
            let mut d = a1.clone();
            d.sign(&ka);
            d.delta_hash()
        };
        publish(&c, &a, &ka, a1);
        publish(&c, &b, &kb, put_delta(&b, 1, None, "x", 2));
        let mut a2 = put_delta(&a, 2, Some(a1_hash), "y", 3);
        a2.ops.push(DeltaOp {
            path: SyncPath("x".into()),
            removes: vec![HeadRef {
                dot: Dot { author: a.clone(), seq: AuthorSeq(1) },
                provenance: a1_hash,
            }],
            put: None,
        });
        publish(&c, &a, &ka, a2);
        (c, a, b)
    }

    #[test]
    fn joining_a_bootstrap_into_a_fresh_replica_installs_the_state_and_later_deltas_chain_onto_it()
    {
        let (source, a, _b) = source();
        let payload = built(&source);
        let verified = verify_native_bootstrap(payload, &group(), &Policy).unwrap();

        let fresh = conn();
        let tx = fresh.unchecked_transaction().unwrap();
        install_checkpoint(&tx, &group(), verified, InstallKind::Fresh, &mut |_| Ok(())).unwrap();
        tx.commit().unwrap();

        assert_eq!(
            crate::native_store::load_state(&fresh, &group()).unwrap(),
            crate::native_store::load_state(&source, &group()).unwrap()
        );
        assert_eq!(
            crate::native_store::load_frontier(&fresh, &group()).unwrap(),
            crate::native_store::load_frontier(&source, &group()).unwrap()
        );
        assert_eq!(
            crate::native_store::namespace_root(
                &crate::native_store::load_state(&fresh, &group()).unwrap()
            )
            .unwrap(),
            crate::native_store::namespace_root(
                &crate::native_store::load_state(&source, &group()).unwrap()
            )
            .unwrap()
        );
        assert!(!crate::native_store::stored_checkpoint_hashes(&fresh, &group()).is_empty());

        // The next delta of an author continues the chain the bootstrap
        // installed, on the fresh replica and on the source alike.
        let ka = device_key(1);
        let tip = crate::native_store::frontier_entry_get(&fresh, &group(), &a).unwrap().unwrap();
        let mut next = put_delta(&a, tip.seq.get() + 1, Some(tip.tip), "z", 4);
        next.sign(&ka);
        crate::native_store::install_verified_delta(&fresh, &group(), &next, &ka.verifying_key())
            .expect("a delta chains onto the installed frontier");
    }

    /// Makes `a` this replica's own author on `c`.
    fn make_own(c: &Connection, a: &AuthorId) {
        crate::author_incarnation::init_schema(c).unwrap();
        c.execute(
            "INSERT INTO author_incarnation (singleton, device_id, incarnation, db_instance_nonce, \
             machine_fingerprint, minted_reason, previous) VALUES (1, ?1, ?2, ?3, X'00', 'install', NULL)",
            rusqlite::params![a.device.as_str(), &a.incarnation.0[..], &[0u8; 16][..]],
        )
        .unwrap();
    }

    /// The sealed state holds more of this replica's own author than this
    /// replica does: another copy wrote under the same identity, so the join
    /// records the report that makes the next authoring rotate.
    #[test]
    fn joining_a_state_with_more_of_the_own_author_reports_it_ahead() {
        let (source, a, _b) = source();
        let verified = verify_native_bootstrap(built(&source), &group(), &Policy).unwrap();
        let fresh = conn();
        make_own(&fresh, &a);

        let tx = fresh.unchecked_transaction().unwrap();
        install_checkpoint(&tx, &group(), verified, InstallKind::Fresh, &mut |_| Ok(())).unwrap();
        tx.commit().unwrap();

        let report = crate::author_incarnation::own_author_ahead(&fresh, GROUP)
            .unwrap()
            .expect("the own-author-ahead report is recorded");
        assert_eq!(report.author, a);
        assert_eq!(report.local, AuthorSeq(0));
        assert_eq!(report.reported, AuthorSeq(2));
    }

    #[test]
    fn a_bootstrap_is_refused_when_anything_it_carries_is_wrong() {
        let (source, _, _) = source();
        let good = built(&source);
        let verify =
            |payload: NativeBootstrap| verify_native_bootstrap(payload, &group(), &Policy).err();
        assert!(verify(good.clone()).is_none(), "the good payload verifies");

        // No seal authorization at all.
        let mut unsealed = good.clone();
        unsealed.seal = None;
        assert!(verify(unsealed).is_some());

        // A seal authorization for another checkpoint.
        let mut other = good.clone();
        other.checkpoint.namespace_root.0[0] ^= 1;
        other.checkpoint.sign(&sealer_key());
        assert!(verify(other).is_some(), "the evidence names a different checkpoint");

        // A checkpoint not signed by the sealer the evidence names.
        let mut forged = good.clone();
        forged.checkpoint.sign(&device_key(9));
        assert!(verify(forged).is_some());

        // A head no delta stands behind.
        let mut headless = good.clone();
        headless.deltas.pop();
        assert!(verify(headless).is_some());

        // A head listed for another dot than its delta's.
        let mut wrong_dot = good.clone();
        wrong_dot.heads[0].dot.seq = AuthorSeq(99);
        assert!(verify(wrong_dot).is_some());

        // A head the checkpoint's namespace root does not commit.
        let mut extra = good.clone();
        let stolen = extra.heads[0].clone();
        extra.heads.push(BootstrapHead { path: SyncPath("elsewhere".into()), ..stolen });
        assert!(verify(extra).is_some());

        // A live head left out together with the delta only it rested on: only
        // the namespace root can tell. (Leaving its delta in is refused on its
        // own: a bundle carries no delta that no live head rests on.)
        let mut omitted = good.clone();
        let gone = omitted.heads.pop().unwrap();
        if !omitted.heads.iter().any(|head| head.provenance == gone.provenance) {
            omitted.deltas.retain(|delta| {
                NativeDelta::from_wire_bytes(&delta.delta_wire).unwrap().delta_hash()
                    != gone.provenance
            });
        }
        let error = verify(omitted).expect("a missing head is refused");
        assert!(error.to_string().contains("namespace root"), "{error}");

        // Author states that do not build the signed author-state root.
        let mut moved = good.clone();
        let AuthorState::Open(entry) = &mut moved.authors[0].state else {
            panic!("the first author is open")
        };
        entry.tip = DeltaHash([0xCD; 32]);
        assert!(verify(moved).is_some());

        // A tampered delta breaks its signature and proof.
        let mut tampered = good.clone();
        let last = tampered.deltas[0].delta_wire.len() - 1;
        tampered.deltas[0].delta_wire[last] ^= 0xFF;
        assert!(verify(tampered).is_some());

        // Content of a live head that is not carried.
        let mut hollow = good;
        hollow.file_versions.clear();
        assert!(verify(hollow).is_some());
    }

    #[test]
    fn a_bootstrap_cannot_be_built_from_a_head_whose_delta_is_gone() {
        let (source, _, _) = source();
        source.execute("DELETE FROM native_delta_bodies WHERE group_id = ?1", [GROUP]).unwrap();
        let error = build_native_recovery_bundle(&source, &group(), &sealer_key()).unwrap_err();
        assert!(error.to_string().contains("not retained"), "{error}");
    }

    // --- a bundle only bootstraps a replica that holds no native state ------

    /// A replica holding the common history: author `c` put `p` (version 1).
    fn with_common() -> Connection {
        let c = conn();
        for seed in 1..=6 {
            crate::dag_store::put_file_version(&c, GROUP, &version(seed)).unwrap();
        }
        let who = author("device-c");
        publish(&c, &who, &device_key(3), put_delta(&who, 1, None, "p", 1));
        c
    }

    fn versions_at(c: &Connection, path: &str) -> Vec<VersionHash> {
        let mut versions: Vec<VersionHash> =
            crate::native_store::native_heads_at(c, &group(), &SyncPath(path.into()))
                .unwrap()
                .into_iter()
                .map(|head| head.payload.version)
                .collect();
        versions.sort();
        versions
    }

    /// Installs `source`'s sealed state into `into` as a fresh join, committing only
    /// an install that succeeded, as the daemon does.
    pub(super) fn try_join(
        source: &Connection,
        into: &Connection,
    ) -> Result<InstalledCheckpoint, CheckpointError> {
        join_bundle(built(source), into)
    }

    pub(super) fn join_bundle(
        bundle: NativeBootstrap,
        into: &Connection,
    ) -> Result<InstalledCheckpoint, CheckpointError> {
        let verified = verify_native_bootstrap(bundle, &group(), &Policy).unwrap();
        let tx = into.unchecked_transaction().unwrap();
        let outcome =
            install_checkpoint(&tx, &group(), verified, InstallKind::Fresh, &mut |_| Ok(()));
        if outcome.is_ok() {
            tx.commit().unwrap();
        }
        outcome
    }

    /// A bundle the sealer made out of `heads` and `frontier` alone, however
    /// little the sealer's own history justifies them: what a hostile but
    /// authorized sealer can produce.
    fn forged_bundle(authors: Vec<BootstrapAuthorState>) -> NativeBootstrap {
        let empty = conn();
        let mut payload = build_native_recovery_bundle(&empty, &group(), &sealer_key()).unwrap();
        payload.checkpoint.author_state_root =
            yadorilink_replica_domain::native_checkpoint::AuthorStateRoot(author_state_root(
                &authors.iter().map(|entry| (entry.author.clone(), entry.state)).collect(),
            ));
        payload.checkpoint.sign(&sealer_key());
        payload.authors = authors;
        sealed(payload)
    }

    /// A policy under which the sealer is not a writer: a viewer, who may
    /// neither write nor seal.
    struct ViewersOnly;

    impl NativeSealPolicy for ViewersOnly {
        fn resolve_authority_key(
            &self,
            key_id: &[u8; 32],
            head: &[u8; 32],
        ) -> Option<ed25519_dalek::VerifyingKey> {
            Policy.resolve_authority_key(key_id, head)
        }

        fn writer_at_policy_point(
            &self,
            _device: &str,
            _signing_key_fingerprint: &[u8; 32],
            _point: &yadorilink_replica_domain::native_checkpoint_seal::SealPolicyPoint,
        ) -> bool {
            false
        }
    }

    /// A policy that vouches for no publication checkpoint: the chain does not
    /// hold the checkpoints' pinned policy points, or the authors were not
    /// writers there. Only the sealer is a writer.
    struct VouchesForNothing;

    impl NativeSealPolicy for VouchesForNothing {
        fn resolve_authority_key(
            &self,
            key_id: &[u8; 32],
            head: &[u8; 32],
        ) -> Option<ed25519_dalek::VerifyingKey> {
            Policy.resolve_authority_key(key_id, head)
        }

        fn writer_at_policy_point(
            &self,
            device: &str,
            _signing_key_fingerprint: &[u8; 32],
            _point: &yadorilink_replica_domain::native_checkpoint_seal::SealPolicyPoint,
        ) -> bool {
            device == "sealer-device"
        }
    }

    /// The authority's signature on a delta's publication checkpoint is not
    /// enough: the verified policy chain must also vouch for the point the
    /// checkpoint pins (the head at that sequence, the author a writer there).
    #[test]
    fn a_bundle_delta_whose_checkpoint_the_policy_does_not_vouch_for_is_refused() {
        let (source, _a, _b) = source();
        let error = verify_native_bootstrap(built(&source), &group(), &VouchesForNothing)
            .err()
            .expect("a delta published under an unvouched policy point is refused");
        assert!(error.to_string().contains("does not vouch"), "{error}");
    }

    /// A delta no live head rests on (one a later delta superseded) is not
    /// history the checkpoint commits to; a bundle carrying it is refused
    /// rather than storing it.
    #[test]
    fn a_bundle_carrying_a_delta_no_live_head_rests_on_is_refused() {
        let (source, a, _b) = source();
        let mut payload = built(&source);
        let superseded = crate::native_store::delta_log_hash(&source, &group(), &a, AuthorSeq(1))
            .unwrap()
            .expect("the superseded delta is logged");
        assert!(
            !payload.heads.iter().any(|head| head.provenance == superseded),
            "sanity: that delta backs no live head"
        );
        payload.deltas.push(delta_evidence(&source, &group(), &superseded).unwrap());
        let error = verify_native_bootstrap(sealed(payload), &group(), &Policy)
            .err()
            .expect("a bundle with an unbacked delta does not verify");
        assert!(error.to_string().contains("no live head rests on"), "{error}");
    }

    fn forged_claim_of_b_at_100() -> NativeBootstrap {
        forged_bundle(vec![BootstrapAuthorState {
            author: author("device-b"),
            state: AuthorState::Open(NativeAuthorFrontierEntry {
                seq: AuthorSeq(100),
                tip: DeltaHash([0xAB; 32]),
            }),
        }])
    }

    fn victim_holding_b1_at_x() -> Connection {
        let victim = conn();
        crate::dag_store::put_file_version(&victim, GROUP, &version(1)).unwrap();
        let b = author("device-b");
        publish(&victim, &b, &device_key(2), put_delta(&b, 1, None, "x", 1));
        victim
    }

    /// A sealer that lists no head and claims `b` is at sequence 100 builds a
    /// bundle that verifies, because the roots match what it listed. Merged into
    /// a replica holding `b:1` it would delete `b:1` and move `b`'s frontier to
    /// a tip no delta chains to. Only a writer may seal, so a sealer without
    /// that authority (a viewer) cannot get such a bundle accepted at all.
    #[test]
    fn a_viewer_sealer_cannot_get_a_bundle_accepted() {
        let victim = victim_holding_b1_at_x();
        let state_before = crate::native_store::load_state(&victim, &group()).unwrap();
        let frontier_before = crate::native_store::load_frontier(&victim, &group()).unwrap();

        let error = verify_native_bootstrap(forged_claim_of_b_at_100(), &group(), &ViewersOnly)
            .err()
            .expect("a bundle sealed by a non-writer does not verify");
        assert!(error.to_string().contains("seal is not authorized"), "{error}");
        assert_eq!(crate::native_store::load_state(&victim, &group()).unwrap(), state_before);
        assert_eq!(crate::native_store::load_frontier(&victim, &group()).unwrap(), frontier_before);
    }

    /// The trust boundary of a writer's seal, stated as what it still allows:
    /// the writer's word covers the completeness of the state, so a fresh replica
    /// takes the claimed tip of `b` beyond anything it holds as given (no carried
    /// delta confirms it), and a bundle that lists no head installs no head. A
    /// replica that holds state of the group takes no bundle at all.
    #[test]
    fn a_writer_sealers_word_covers_the_state_a_fresh_replica_installs() {
        let fresh = conn();
        let outcome = join_bundle(forged_claim_of_b_at_100(), &fresh)
            .expect("a writer's bundle is installed by a replica with no state");
        assert!(outcome.changed_paths.is_empty());
        let entry = crate::native_store::frontier_entry_get(&fresh, &group(), &author("device-b"))
            .unwrap()
            .unwrap();
        assert_eq!((entry.seq, entry.tip), (AuthorSeq(100), DeltaHash([0xAB; 32])));

        let victim = victim_holding_b1_at_x();
        assert!(matches!(
            join_bundle(forged_claim_of_b_at_100(), &victim),
            Err(CheckpointError::NotEmpty)
        ));
        assert_eq!(versions_at(&victim, "x"), vec![version(1).version_hash]);
    }

    /// `a` puts `x` and then removes it: the live heads are empty while the
    /// frontier is at `a:2`. Returns the source holding both deltas and the
    /// hash of the first.
    fn put_then_delete_at_x() -> (Connection, AuthorId, DeltaHash) {
        let source = conn();
        crate::dag_store::put_file_version(&source, GROUP, &version(1)).unwrap();
        let (a, ka) = (author("device-a"), device_key(1));
        let a1 = put_delta(&a, 1, None, "x", 1);
        let a1_hash = signed_hash(a1.clone(), &ka);
        publish(&source, &a, &ka, a1);
        let a2 = NativeDelta {
            ops: vec![DeltaOp {
                path: SyncPath("x".into()),
                removes: vec![HeadRef {
                    dot: Dot { author: a.clone(), seq: AuthorSeq(1) },
                    provenance: a1_hash,
                }],
                put: None,
            }],
            ..put_delta(&a, 2, Some(a1_hash), "x", 1)
        };
        publish(&source, &a, &ka, a2);
        (source, a, a1_hash)
    }

    /// A replica recovered from a bundle holds the sender's whole frontier but
    /// bodies only for the deltas the live heads rest on. A replica that holds
    /// an earlier part of the history cannot be served the rest by deltas, so
    /// it rebootstraps onto the recovered replica's sealed state (see the rebootstrap
    /// install) and never joins it.
    #[test]
    fn a_recovered_replica_cannot_serve_a_lagging_one_and_its_bundle_is_not_joined() {
        let (origin, a, a1_hash) = put_then_delete_at_x();
        let recovered = conn();
        try_join(&origin, &recovered).unwrap();
        assert!(
            crate::native_store::load_state(&recovered, &group()).unwrap().heads.is_empty(),
            "nothing of the history is live, so no body came with the bundle"
        );

        let lagging = conn();
        crate::dag_store::put_file_version(&lagging, GROUP, &version(1)).unwrap();
        publish(&lagging, &a, &device_key(1), put_delta(&a, 1, None, "x", 1));
        assert_eq!(versions_at(&lagging, "x"), vec![version(1).version_hash]);

        let since = crate::native_replication::frontier_since(&lagging, &group()).unwrap();
        let refusal =
            crate::native_replication::deltas_to_serve(&recovered, &group(), &since, 100).unwrap();
        let floor = crate::native_history_floor::history_floor(&recovered, &group())
            .unwrap()
            .expect("a join sets the history floor");
        assert_eq!(
            refusal.unwrap_err(),
            crate::native_replication::ServeRefusal::HistoryTruncated {
                author: a.clone(),
                seq: AuthorSeq(2),
                checkpoint_id: floor.checkpoint_id,
                frontier_root: floor.floor_frontier_root,
            },
            "the recovered replica cannot supply the delta the lagging one lacks, and says \
             where its history begins"
        );

        // A replica that holds part of the history takes no bundle: it rebootstraps.
        assert!(matches!(try_join(&recovered, &lagging), Err(CheckpointError::NotEmpty)));
        assert_eq!(versions_at(&lagging, "x"), vec![version(1).version_hash]);
        let _ = a1_hash;
    }

    #[test]
    fn a_join_arms_exactly_the_paths_of_the_heads_it_installs() {
        let (online, fresh) = (with_common(), conn());
        let outcome = try_join(&online, &fresh).unwrap();
        let armed: Vec<String> = fresh
            .prepare("SELECT path FROM projection_obligations WHERE group_id = ?1")
            .unwrap()
            .query_map([GROUP], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(armed, vec!["p".to_owned()]);
        assert_eq!(outcome.changed_paths, vec!["p".to_owned()]);
    }

    // --- deltas held before the bundle arrived -----------------------------

    /// Admits `delta` into `c` as a peer's delta arrives: proof-carrying, so a
    /// delta that has to wait keeps its publication evidence.
    fn receive(
        c: &Connection,
        who: &AuthorId,
        key: &SigningKey,
        mut delta: NativeDelta,
    ) -> NativeAdmission {
        delta.sign(key);
        let leaves = [delta.delta_hash().0];
        let checkpoint = AuthorizationCheckpoint {
            group_id: GROUP.into(),
            device_id: who.device.0.clone(),
            signing_key_fingerprint: fingerprint_signing_key(&key.verifying_key()),
            merkle_root: merkle_root(&leaves),
            leaf_count: 1,
            checkpoint_seq: delta.seq.get(),
            signer_key_id: fingerprint_signing_key(&authority_key().verifying_key()),
            policy_epoch: 0,
            policy_seq: 1,
            policy_head: [0; 32],
            issued_at_unix: 0,
        };
        let encoded = canonical_signing_bytes(&checkpoint);
        let signature = sign_checkpoint(&checkpoint, &authority_key());
        crate::native_admission::admit_published_native_delta_on_conn(
            c,
            &group(),
            &delta.to_wire_bytes(),
            &checkpoint_hash(&encoded, &signature),
            &encoded,
            &signature,
            &key.verifying_key().to_bytes(),
            &build_merkle_proof(&leaves, 0),
            &|_| None,
            |key_id, head| Policy.resolve_authority_key(key_id, head),
        )
        .unwrap()
    }

    fn hold_rows(c: &Connection) -> i64 {
        c.query_row("SELECT COUNT(*) FROM native_delta_holds WHERE group_id = ?1", [GROUP], |r| {
            r.get(0)
        })
        .unwrap()
    }

    fn signed_hash(mut delta: NativeDelta, key: &SigningKey) -> DeltaHash {
        delta.sign(key);
        delta.delta_hash()
    }

    /// A delta that arrived before its predecessor waits for it. The install
    /// clears what waited on the replaced state, so no hold outlives it; the
    /// delta is admitted when it is delivered again.
    #[test]
    fn a_delta_held_before_the_install_is_dropped_and_admitted_when_it_arrives_again() {
        let (a, ka) = (author("device-a"), device_key(1));
        let a1 = put_delta(&a, 1, None, "x", 1);
        let a1_hash = signed_hash(a1.clone(), &ka);
        let source = conn();
        crate::dag_store::put_file_version(&source, GROUP, &version(1)).unwrap();
        publish(&source, &a, &ka, a1);

        let fresh = conn();
        for seed in 1..=2 {
            crate::dag_store::put_file_version(&fresh, GROUP, &version(seed)).unwrap();
        }
        let a2 = put_delta(&a, 2, Some(a1_hash), "y", 2);
        let admitted = receive(&fresh, &a, &ka, a2.clone());
        assert!(matches!(admitted, NativeAdmission::Held { .. }), "{admitted:?}");
        assert_eq!(hold_rows(&fresh), 1);

        try_join(&source, &fresh).unwrap();

        assert_eq!(hold_rows(&fresh), 0, "the install clears what waited on the old state");
        assert!(versions_at(&fresh, "y").is_empty());
        assert_eq!(versions_at(&fresh, "x"), vec![version(1).version_hash]);

        // The ordinary delivery of the delta chains onto the installed frontier.
        let again = receive(&fresh, &a, &ka, a2);
        assert!(matches!(again, NativeAdmission::Admitted { .. }), "{again:?}");
        assert_eq!(versions_at(&fresh, "y"), vec![version(2).version_hash]);
    }

    // --- the projection state ----------------------------------------------

    // --- auxiliary native tables around a join -------------------------------

    fn roots_of(c: &Connection) -> ([u8; 32], [u8; 32]) {
        let roots = crate::native_replication::summary_roots(c, &group()).unwrap();
        (roots.namespace_root, roots.author_state_root)
    }

    /// A replica with no native state can hold closure and checkpoint rows left
    /// from an earlier life of the group. They describe a state that no longer
    /// exists: after the join the closures and the checkpoint are the bundle's,
    /// so the replica's roots are the sealer's.
    #[test]
    fn a_join_replaces_leftover_closures_and_checkpoints_of_a_replica_with_no_native_state() {
        let (source, a, b) = source();
        close_author(&source, &group(), &a);
        let bundle = built(&source);
        let expected_checkpoint = bundle.checkpoint.clone();

        let stale = conn();
        // `b` was closed in an earlier life; the bundle says it is open. `a`
        // was never closed here; the bundle says it is. The leftover is a state
        // row with no closure behind it.
        stale
            .execute(
                "INSERT INTO native_closed_authors \
                 (group_id, author, incarnation, closed_at_unixtime) VALUES (?1, ?2, ?3, 1)",
                rusqlite::params![GROUP, b.device.as_str(), b.incarnation.0.as_slice()],
            )
            .unwrap();
        let mut old_checkpoint = expected_checkpoint.clone();
        old_checkpoint.namespace_root.0[0] ^= 1;
        old_checkpoint.sign(&sealer_key());
        crate::native_store::install_checkpoint(
            &stale,
            &group(),
            &old_checkpoint,
            &sealer_key().verifying_key(),
        )
        .unwrap();
        stale
            .execute(
                "UPDATE native_checkpoints SET installed_at_unixtime = installed_at_unixtime + 1000",
                [],
            )
            .unwrap();

        join_bundle(bundle, &stale).unwrap();

        assert_eq!(roots_of(&stale), roots_of(&source), "the sealer's author states win");
        assert!(!crate::native_store::is_closed(&stale, &group(), &b).unwrap());
        assert!(crate::native_store::is_closed(&stale, &group(), &a).unwrap());
        assert_eq!(
            crate::native_store::stored_checkpoint_hashes(&stale, &group()),
            vec![expected_checkpoint.checkpoint_hash().0],
            "the join replaced the stale checkpoint with the sealer's"
        );
    }
}
