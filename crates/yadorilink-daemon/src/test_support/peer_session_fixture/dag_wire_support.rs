//! Reusable native-delta producer support for over-the-wire integration
//! scenarios. The `tests/dst_support/` module is gated on the simulation
//! cfg, so a plain `cargo test` integration test cannot reuse it.
//!
//! 1. [`DagProducer`] — a "commit a local edit into native state" routine that
//!    mirrors the daemon's FS-edit -> signed-delta producer. Its
//!    [`DagProducer::commit_create`] stores the content block and then calls
//!    `LocalMutationStore::commit_local_mutations_batch` through
//!    `test_support::local_seam` — the port method the watcher's flush calls
//!    to sign a delta, persist
//!    the referenced `FileVersion`, advance the group's native head, and upsert the
//!    index row, all in one transaction. The caller then drives
//!    `PeerSyncSession::announce_local_commit` (what the daemon's
//!    `DaemonState::on_local_native_commit` does for a connected peer) so the
//!    peer's heads-announce carries the new commit. Every API used here is
//!    public `yadorilink_daemon::replica_coordinator`/
//!    `yadorilink_replica_domain` surface. The daemon only adds the netmap
//!    adapter and the broadcast wrapper on top, so the native producer is fully
//!    exercisable directly against a `ReplicaCoordinator` — which is why this
//!    support belongs at this layer and not inside the daemon crate itself.

#![allow(dead_code)] // reusable helper; not every scenario uses every method

use std::sync::Arc;

use crate::replica_coordinator::ReplicaCoordinator;
use ed25519_dalek::SigningKey;
use yadorilink_peer_session::peer_session::RootCommitAuthorityProvider;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};
use yadorilink_replica_domain::ids::BlockHash;
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;

/// A `RootCommitAuthorityProvider` that always grants a lease, backed by one
/// process-lifetime `RootLease::for_tests()` per provider instance — the same
/// "no real link lifecycle" test lease `RootCommitPermit::for_tests` shares
/// process-wide, but scoped per device here so two devices in one process
/// (as this module's two-device wire scenarios construct) never share a
/// lease's admission counter.
///
/// `yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()` wires the deny-by-default
/// `DenyRootCommitAuthorityProvider` (mirroring the daemon-facing
/// `PeerSyncSessionOneTimeDeps::denied()`), which makes every `materialize`
/// call fail with "no live root-commit authority" — correct for a caller
/// that never established a link, but wrong for a test standing in for the
/// daemon's real per-link `RootLease` (installed by
/// `yadorilink-daemon`'s `DaemonState`, see `root_commit_authority.rs`,
/// once `start_link_watch` acquires the link's `SyncRootLock`). This mirrors
/// the crate-internal `AlwaysValidRootCommitAuthorityProvider` test default
/// (`peer_session.rs`), which is not part of this crate's public surface, so
/// integration tests need their own equivalent.
pub struct AlwaysValidRootCommitAuthorityProvider {
    lease: Arc<RootLease>,
}

impl AlwaysValidRootCommitAuthorityProvider {
    pub fn shared() -> Arc<dyn RootCommitAuthorityProvider> {
        Arc::new(Self { lease: Arc::new(RootLease::for_tests()) })
    }
}

impl RootCommitAuthorityProvider for AlwaysValidRootCommitAuthorityProvider {
    fn root_lease_for(&self, _group_id: &str) -> Option<Arc<RootLease>> {
        Some(self.lease.clone())
    }
}

/// Builds a real, self-consistent `(checkpoints, published_changes)` pair
/// for `changes` (all authored by the SAME device), covering a
/// `proof-carrying-change` wire batch a real receiver accepts. `signing_key` signs the
/// checkpoint too, standing in for the coordination-plane authority: these
/// integration tests have no real authority/policy chain, so a device
/// signing its own checkpoint is a faithful, minimal stand-in.
/// One self-signed checkpoint covering `changes` (all authored by the SAME
/// device), plus each change's own Merkle proof against it -- the raw pieces
/// both [`self_signed_checkpointed_batch`] (wire-frame proto shape, for
/// direct injection) and [`attach_self_signed_checkpoint`] (storage
/// attachment, for the real reconcile/heads-announce wire path) need. See
/// `self_signed_checkpointed_batch`'s own doc comment for why a device
/// signing its own checkpoint is a faithful, minimal stand-in for these
/// integration tests, which have no real coordination-plane authority.
struct SelfSignedCheckpoint {
    checkpoint_hash: [u8; 32],
    checkpoint_encoded: Vec<u8>,
    signature: Vec<u8>,
    author_signing_public_key: [u8; 32],
    group_id: String,
    device_id: String,
    checkpoint_seq: u64,
    proofs: Vec<yadorilink_replica_domain::authorization_checkpoint::MerkleProof>,
}

/// The native counterpart of [`attach_self_signed_checkpoint`]: self-signs one
/// covering checkpoint per group over every native delta `device_id` authored
/// that carries no publication evidence yet, and attaches it, so a peer's block
/// request for their content is authorized. Mirrors the daemon's native
/// checkpoint flush minus the coordination-plane round trip.
pub fn publish_pending_native_deltas(
    state: &ReplicaCoordinator,
    signing_key: &SigningKey,
    device_id: &str,
) {
    use yadorilink_replica_domain::authorization_checkpoint::{
        build_merkle_proof, canonical_signing_bytes, checkpoint_hash, encode_merkle_proof,
        fingerprint_signing_key, merkle_root, sign_checkpoint, AuthorizationCheckpoint,
    };
    use yadorilink_replica_domain::signed_delta::NativeDelta;
    let pending: Vec<(String, Vec<u8>)> = state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT b.group_id, b.encoded_delta FROM native_delta_bodies b \
                 WHERE b.author = ?1 AND NOT EXISTS ( \
                     SELECT 1 FROM native_delta_authorization a WHERE a.delta_hash = b.delta_hash) \
                 ORDER BY b.group_id, b.seq",
            )?;
            let rows = stmt.query_map([device_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .unwrap();
    let mut by_group: std::collections::BTreeMap<String, Vec<NativeDelta>> = Default::default();
    for (group, body) in pending {
        by_group.entry(group).or_default().push(NativeDelta::from_wire_bytes(&body).unwrap());
    }
    for (group, deltas) in by_group {
        let leaves: Vec<[u8; 32]> = deltas.iter().map(|d| d.delta_hash().0).collect();
        let seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        let key_fingerprint = fingerprint_signing_key(&signing_key.verifying_key());
        let checkpoint = AuthorizationCheckpoint {
            group_id: group.clone(),
            device_id: device_id.to_owned(),
            signing_key_fingerprint: key_fingerprint,
            merkle_root: merkle_root(&leaves),
            leaf_count: leaves.len() as u64,
            checkpoint_seq: seq,
            signer_key_id: key_fingerprint,
            policy_epoch: 0,
            policy_seq: 0,
            policy_head: [0; 32],
            issued_at_unix: 0,
        };
        let encoded = canonical_signing_bytes(&checkpoint);
        let signature = sign_checkpoint(&checkpoint, signing_key);
        let hash = checkpoint_hash(&encoded, &signature);
        let entries: Vec<_> = deltas
            .iter()
            .enumerate()
            .map(|(index, delta)| {
                (delta.delta_hash(), encode_merkle_proof(&build_merkle_proof(&leaves, index)))
            })
            .collect();
        state
            .database()
            .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::native_publication::attach_authorization_evidence(
                    conn,
                    &hash,
                    &group,
                    device_id,
                    seq,
                    &encoded,
                    &signature,
                    &signing_key.verifying_key().to_bytes(),
                    &entries,
                )
            })
            .expect("attach self-signed native evidence");
    }
}

/// A device-local native-delta producer over a real `ReplicaCoordinator` + block store,
/// mirroring the daemon's FS-edit -> signed-delta flow. Hold one per simulated
/// device; commits advance that device's own native head, and the owning
/// `PeerSyncSession` announces them with `announce_local_commit`.
pub struct DagProducer {
    state: Arc<ReplicaCoordinator>,
    store: Arc<dyn yadorilink_local_storage::BlockContentStore>,
    device_id: String,
    emitter: Arc<LocalAuthorKey>,
    signing_key: SigningKey,
}

impl DagProducer {
    /// `signing_key` is this device's own Ed25519 key; the peer must resolve
    /// its verifying key to admit the changes it signs.
    pub fn new(
        state: Arc<ReplicaCoordinator>,
        store: Arc<dyn yadorilink_local_storage::BlockContentStore>,
        device_id: &str,
        signing_key: SigningKey,
    ) -> Self {
        let key_copy = signing_key.clone();
        let emitter = Arc::new(
            crate::test_support::local_seam::replica_author_key(&state, device_id, signing_key)
                .expect("the producer's replica has this device's author incarnation"),
        );
        Self { state, store, device_id: device_id.to_string(), emitter, signing_key: key_copy }
    }

    /// Commits a single-block file `Create` into native state exactly as the daemon
    /// producer would: store the content block, build the `FileVersion` the same
    /// way `LocalChangeProcessor::content_op` does (block hash + size + the given
    /// `mtime`), then emit the signed delta and upsert the index row via
    /// `test_support::local_seam::commit_local_upsert`.
    ///
    /// `mtime_unix_nanos` is set explicitly so a scenario can invert mtime
    /// against commit order, which determines the display rank. Returns the
    /// committed `FileRecord`.
    pub fn commit_create(
        &self,
        group_id: &str,
        path: &str,
        content: &[u8],
        mtime_unix_nanos: i64,
    ) -> FileRecord {
        assert!(!content.is_empty(), "commit_create needs non-empty content to carry one block");
        let hash_hex = self.store.put(content).expect("store content block");
        let hash = hex::decode(&hash_hex).expect("block hash is hex");
        // Mirrors what `LocalChangeProcessor` does for a real local edit
        // (`record_group_block_provenance`'s doc comment): without this, a
        // peer session's block-serving/restore path refuses this block as
        // never having been obtained through the group.
        self.state.record_block_provenance(group_id, std::slice::from_ref(&hash)).unwrap();
        let size = content.len();

        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(hash.clone()), size: size as u32 }],
            size as u64,
            FileMeta {
                mtime_unix_nanos,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );

        let record = FileRecord {
            path: path.to_string(),
            size: size as u64,
            mtime_unix_nanos,
            blocks: vec![BlockInfo { hash, offset: 0, size: size as u32 }],
            deleted: false,
        };

        crate::test_support::local_seam::commit_local_upsert(
            &self.state,
            group_id,
            &record,
            &self.device_id,
            &version,
            None,
            &self.emitter,
            &RootCommitPermit::for_tests(),
        )
        .expect("emit signed change and upsert index row");
        record
    }

    /// Commits an empty (zero-block) file `Create`. The receiving peer needs no
    /// block request to materialize it, so — unlike [`commit_create`] — this
    /// one never blocks on a block response. That makes it usable as an
    /// interleaved control signal: a message whose arrival at the index proves
    /// the receiver actually dequeued and handled it.
    pub fn commit_create_empty(
        &self,
        group_id: &str,
        path: &str,
        mtime_unix_nanos: i64,
    ) -> (FileRecord, FileVersion) {
        let version = FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        let record = FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos,
            blocks: vec![],
            deleted: false,
        };
        crate::test_support::local_seam::commit_local_upsert(
            &self.state,
            group_id,
            &record,
            &self.device_id,
            &version,
            None,
            &self.emitter,
            &RootCommitPermit::for_tests(),
        )
        .expect("emit signed change and upsert index row");
        (record, version)
    }

    /// [`commit_create`] plus the `FileVersion` it built, so a caller can hand
    /// the version to [`last_commit_as_wire_batch`]. Mirrors `commit_create`'s
    /// version construction exactly.
    pub fn commit_create_returning_version(
        &self,
        group_id: &str,
        path: &str,
        content: &[u8],
        mtime_unix_nanos: i64,
    ) -> (FileRecord, FileVersion) {
        let record = self.commit_create(group_id, path, content, mtime_unix_nanos);
        let hash = record.blocks[0].hash.clone();
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(hash), size: content.len() as u32 }],
            content.len() as u64,
            FileMeta {
                mtime_unix_nanos,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        (record, version)
    }

    /// Publishes every change committed for `group_id` since the last call
    /// (or since construction) -- see [`attach_self_signed_checkpoint`]'s
    /// own doc comment for why this is required before the real
    /// reconcile/heads-announce wire path (`PeerSyncSession::
    /// announce_local_commit`/`send_change_batch`) will ever pick a commit
    /// up. A no-op if nothing is pending for this group.
    pub fn publish_pending(&self, _group_id: &str) {
        publish_pending_native_deltas(&self.state, &self.signing_key, &self.device_id);
    }
}
