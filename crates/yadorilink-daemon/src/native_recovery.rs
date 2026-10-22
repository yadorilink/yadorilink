//! Native recovery in the live daemon: sealing this device's state for a peer
//! that holds none, and verifying and installing a state a peer sealed.
//!
//! A peer that holds no native state of the group (a new device, a new member,
//! a replica with a lost database) asks for recovery. The serving device seals
//! its current native state, asks the group's authority to authorize that exact
//! checkpoint (the authority applies its own live writer check: authorized
//! writers are trusted for the completeness of what they seal), and sends the authorized bundle. The receiving device verifies the
//! authorization against its own view of the group's policy chain, re-derives
//! every head from its signed delta, recomputes the signed roots and only then
//! installs the bundle (see `yadorilink_sync_sqlite::native_bootstrap`). A
//! device that already holds state of the group replaces it only through a
//! rebootstrap (see `crate::native_rebootstrap`); a device that holds none installs
//! the bundle as a first join (see `install_checkpoint`).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use yadorilink_replica_domain::authorization_checkpoint::{build_merkle_proof, merkle_root};
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::native_checkpoint_seal::SealPolicyPoint;
use yadorilink_replica_domain::native_checkpoint_seal::{
    native_checkpoint_seal_leaf, NativeCheckpointSealProof, NativeSealPolicy,
};
use yadorilink_replica_domain::protocol5::RefusalReason;
use yadorilink_sync_sqlite::native_bootstrap::{
    adopt_own_seal, build_native_recovery_bundle, verify_native_bootstrap, NativeBootstrap,
};
use yadorilink_sync_sqlite::native_bootstrap_codec::{
    decode_recovery_bundle, encode_recovery_bundle,
};
use yadorilink_sync_sqlite::native_checkpoint_install::{install_checkpoint, InstallKind};

use crate::checkpoint_source::CheckpointPurpose;
use crate::daemon_state::{DaemonState, GroupPolicyResolution};

/// The head of the policy chain before its first record.
const GENESIS_POLICY_HEAD: [u8; 32] = [0; 32];

/// What the replication driver asks of the daemon for recovery, so the driver
/// depends on no daemon state type.
pub trait RecoveryPort: Send + Sync {
    /// This device's state of `group`, sealed and authorized, as the bundle's
    /// canonical bytes; or why it cannot be served.
    fn serve<'a>(
        &'a self,
        group: &'a FolderGroupId,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, RefusalReason>> + Send + 'a>>;

    /// Verifies a bundle a peer sealed and takes it as `group`'s state: a first join for a device
    /// that holds none, a rebootstrap for one that does. Returns how many paths a first join
    /// changed (a rebootstrap reports none: its changes reach the folder through the
    /// materializer), or why the bundle was refused or the rebootstrap did not run.
    /// Synchronous and long for a rebootstrap: it runs on a blocking thread.
    fn apply(&self, group: &FolderGroupId, bundle: &[u8]) -> Result<usize, String>;
}

/// The group's signed policy chain as a native seal is verified against.
pub(crate) enum PolicyView<'a> {
    Verified(&'a crate::change_policy::GroupPolicyState),
    Genesis { service_key: Option<[u8; 32]> },
}

impl NativeSealPolicy for PolicyView<'_> {
    fn resolve_authority_key(
        &self,
        signer_key_id: &[u8; 32],
        policy_head: &[u8; 32],
    ) -> Option<VerifyingKey> {
        match self {
            Self::Verified(policy) => policy.resolve_authority_key(signer_key_id, policy_head),
            Self::Genesis { service_key } => {
                let key = (*service_key)?;
                let fingerprint: [u8; 32] = Sha256::digest(key).into();
                (*policy_head == GENESIS_POLICY_HEAD && fingerprint == *signer_key_id)
                    .then(|| VerifyingKey::from_bytes(&key).ok())
                    .flatten()
            }
        }
    }

    /// A publication checkpoint, or a seal, is vouched for by the verified
    /// chain alone: at the genesis point there are no grants, so only the
    /// pre-rotation empty chain qualifies; at a later point the chain must hold
    /// that head at that sequence with the device a writer under the
    /// checkpoint's key. A bundle's sealer is accepted on the same terms: it
    /// is a writer there, and a viewer never is.
    fn writer_at_policy_point(
        &self,
        device: &str,
        signing_key_fingerprint: &[u8; 32],
        point: &SealPolicyPoint,
    ) -> bool {
        match self {
            Self::Verified(policy) => policy.writer_at_policy_point(
                device,
                signing_key_fingerprint,
                point.seq,
                &point.head,
            ),
            Self::Genesis { .. } => point.seq == 0 && point.head == GENESIS_POLICY_HEAD,
        }
    }
}

/// The daemon's [`RecoveryPort`]. Holds the state weakly: a driver task must
/// not keep a stopped daemon alive.
pub struct DaemonRecovery {
    state: Weak<DaemonState>,
    /// When each group's state was last sealed for any peer: shared by every
    /// connection's port, so the cooldown is device-wide.
    last_sealed: SealLog,
}

/// When each group's state was last sealed, shared across connections.
pub type SealLog = Arc<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>>;

/// The shortest gap between two seals of one group's state, whichever peers ask:
/// each takes the exclusive writer gate and a coordination round trip, so
/// several peers (or one peer over several connections) cannot multiply them.
const SEAL_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);

impl DaemonRecovery {
    pub fn new(state: &Arc<DaemonState>) -> Self {
        Self { state: Arc::downgrade(state), last_sealed: state.native_replication.seal_log() }
    }

    /// A port with a seal log of its own, so a test can ask again without waiting out
    /// the device-wide cooldown.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_private_seal_log_for_test(state: &Arc<DaemonState>) -> Self {
        Self { state: Arc::downgrade(state), last_sealed: SealLog::default() }
    }

    /// Whether `group` may be sealed now; when it may, records that it is.
    fn admit_seal(&self, group: &FolderGroupId) -> bool {
        let mut last = self.last_sealed.lock().unwrap_or_else(|p| p.into_inner());
        if last.get(&group.0).is_some_and(|at| at.elapsed() < SEAL_COOLDOWN) {
            return false;
        }
        last.insert(group.0.clone(), std::time::Instant::now());
        true
    }
}

/// Adopts the checkpoint this device sealed under the group's current policy. Fails
/// when the policy is withheld or the write fails, and then nothing is adopted.
async fn adopt_sealed_checkpoint(
    state: &Arc<DaemonState>,
    group: &FolderGroupId,
    sealed: &yadorilink_sync_sqlite::native_bootstrap::NativeBootstrap,
) -> Result<(), ()> {
    let resolution = state.resolve_group_policy(group.as_str());
    let (db, group_owned, sealed) =
        (state.replica_coordinator.database(), group.clone(), sealed.clone());
    let service_key = state.authority.pinned_coordination_service_key();
    let adopted = tokio::task::spawn_blocking(move || {
        db.write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            let view = match &resolution {
                GroupPolicyResolution::Verified(policy) => PolicyView::Verified(policy),
                GroupPolicyResolution::Bootstrap => PolicyView::Genesis { service_key },
                GroupPolicyResolution::Withhold => {
                    return Err(yadorilink_sync_sqlite::SyncSqliteError::InvalidInput(
                        "the group's policy is withheld".into(),
                    ))
                }
            };
            adopt_own_seal(tx, &group_owned, &sealed, &view)
        })
    })
    .await;
    match adopted {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            tracing::warn!(%error, group = %group.0, "native recovery: did not adopt the checkpoint just sealed");
            Err(())
        }
        Err(_) => {
            tracing::warn!(group = %group.0, "native recovery: adopting the checkpoint just sealed was interrupted");
            Err(())
        }
    }
}

/// The deterministic id of the authorization request for sealing `leaf`: asking
/// again for the same seal replays the authority's earlier decision.
fn seal_request_id(group: &str, device: &str, leaf: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(group.as_bytes());
    hasher.update([0u8]);
    hasher.update(device.as_bytes());
    hasher.update([0u8]);
    hasher.update(leaf);
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Seals this device's native state of `group`: builds the bundle, has the group's authority
/// authorize that exact checkpoint, and adopts it as the checkpoint this device trusts. What is
/// served to a peer, and what a rebootstrap's replacement checkpoint is, both come from here.
pub(crate) async fn seal_own_state(
    state: &Arc<DaemonState>,
    group: &FolderGroupId,
) -> Result<NativeBootstrap, RefusalReason> {
    let signing_key = state.device_signing_key().ok_or(RefusalReason::NotFound)?;
    let source = state.seal_checkpoint_source().ok_or(RefusalReason::NotFound)?;

    // Sealing and reading the state are one step: the bundle must be
    // exactly what the checkpoint commits to.
    let (db, group_owned, key) =
        (state.replica_coordinator.database(), group.clone(), signing_key.clone());
    let built = tokio::task::spawn_blocking(move || {
        db.write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            build_native_recovery_bundle(tx, &group_owned, &key)
        })
    })
    .await
    .map_err(|_| RefusalReason::Overloaded)?
    .map_err(|error| {
        tracing::warn!(%error, group = %group.0, "native recovery: could not seal this state");
        RefusalReason::NotFound
    })?;
    let mut bundle = built;

    let leaf = native_checkpoint_seal_leaf(group.as_str(), &bundle.checkpoint);
    let request_id = seal_request_id(group.as_str(), &state.device_id, &leaf);
    let Some((authority_checkpoint, signature)) = source
        .request_authorization_checkpoint(
            group.as_str(),
            &state.device_id,
            &request_id,
            merkle_root(&[leaf]),
            1,
            CheckpointPurpose::Seal,
        )
        .await
    else {
        return Err(RefusalReason::Overloaded);
    };
    bundle.seal = Some(
        NativeCheckpointSealProof {
            authority_checkpoint,
            authority_checkpoint_signature: signature,
            sealer_public_key: signing_key.verifying_key().to_bytes(),
            merkle_proof: build_merkle_proof(&[leaf], 0),
        }
        .into_evidence(),
    );
    // The sealer adopts what it sealed the way a joiner would, so its own
    // trusted checkpoint and the frontier it covers are on record. A bundle
    // is served only for a checkpoint the sealer holds. The seal is
    // deterministic for an unchanged state, so asking again retries the
    // adoption.
    if adopt_sealed_checkpoint(state, group, &bundle).await.is_err() {
        return Err(RefusalReason::Overloaded);
    }
    Ok(bundle)
}

impl RecoveryPort for DaemonRecovery {
    fn serve<'a>(
        &'a self,
        group: &'a FolderGroupId,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, RefusalReason>> + Send + 'a>> {
        Box::pin(async move {
            let state = self.state.upgrade().ok_or(RefusalReason::Overloaded)?;
            state.device_signing_key().ok_or(RefusalReason::NotFound)?;
            if !self.admit_seal(group) {
                return Err(RefusalReason::Overloaded);
            }
            let bundle = match seal_own_state(&state, group).await {
                Ok(bundle) => bundle,
                Err(reason) => {
                    // Nothing was sealed, so the retry is not a repeat of a seal: the
                    // cooldown must not hold off the ask that follows this refusal.
                    self.last_sealed.lock().unwrap_or_else(|p| p.into_inner()).remove(&group.0);
                    return Err(reason);
                }
            };
            encode_recovery_bundle(&bundle).map_err(|error| {
                tracing::warn!(%error, group = %group.0, "native recovery: could not encode the bundle");
                RefusalReason::NotFound
            })
        })
    }

    /// A device that holds no state of the group installs the bundle as a first join; a device
    /// that holds state replaces it through the rebootstrap machine, which preserves what the
    /// replacement would lose and replays this device's own intent on top.
    fn apply(&self, group: &FolderGroupId, bundle: &[u8]) -> Result<usize, String> {
        let state = self.state.upgrade().ok_or_else(|| "the daemon is stopping".to_owned())?;
        let payload = decode_recovery_bundle(bundle).map_err(|error| error.to_string())?;
        let holds_state = state
            .replica_coordinator
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::native_replication::frontier_entries(conn, group, false)
                    .map(|entries| !entries.is_empty())
            })
            .map_err(|error| error.to_string())?;
        if holds_state {
            return crate::native_rebootstrap::run(&state, group, payload)
                .map(|()| 0)
                .map_err(|error| error.to_string());
        }
        let resolution = state.resolve_group_policy(group.as_str());
        let installed = state
            .replica_coordinator
            .database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                let payload = payload.clone();
                let verified = match &resolution {
                    GroupPolicyResolution::Verified(policy) => {
                        verify_native_bootstrap(payload, group, &PolicyView::Verified(policy))?
                    }
                    GroupPolicyResolution::Bootstrap => verify_native_bootstrap(
                        payload,
                        group,
                        &PolicyView::Genesis {
                            service_key: state.authority.pinned_coordination_service_key(),
                        },
                    )?,
                    GroupPolicyResolution::Withhold => {
                        return Err(yadorilink_sync_sqlite::SyncSqliteError::InvalidInput(
                            "the group's policy is withheld".into(),
                        ))
                    }
                };
                install_checkpoint(tx, group, verified, InstallKind::Fresh, &mut |_| Ok(()))
                    .map_err(|error| {
                        yadorilink_sync_sqlite::SyncSqliteError::InvalidInput(error.to_string())
                    })
            })
            .map_err(|error| error.to_string())?;
        state.replica_coordinator.notify_materialization_wake();
        Ok(installed.changed_paths.len())
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::change_policy::policy_signing::grant_record;
    use crate::change_policy::{
        verify_group_policy_log, GroupPolicyLog, GroupPolicyState, WriterRole,
    };

    const GROUP: &str = "seal-group";

    fn authority() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn fingerprint(seed: u8) -> [u8; 32] {
        Sha256::digest([seed; 32]).into()
    }

    /// A chain that grants an owner, an editor and a viewer, in that order.
    fn policy() -> (GroupPolicyState, Vec<[u8; 32]>) {
        let roles = [
            ("device-owner", 1u8, WriterRole::Owner),
            ("device-editor", 2, WriterRole::Editor),
            ("device-viewer", 3, WriterRole::Viewer),
        ];
        let mut records = Vec::new();
        let mut heads = Vec::new();
        let mut prev = [0u8; 32];
        for (index, (device, seed, role)) in roles.into_iter().enumerate() {
            let record = grant_record(
                &authority(),
                GROUP,
                index as u64 + 1,
                prev,
                device,
                fingerprint(seed),
                role,
            );
            prev = record.record_hash.as_slice().try_into().unwrap();
            heads.push(prev);
            records.push(record);
        }
        let log = GroupPolicyLog {
            group_id: GROUP.into(),
            current_seq: records.len() as u64,
            current_epoch: 0,
            policy_head: prev.to_vec(),
            records,
        };
        (verify_group_policy_log(&authority().verifying_key().to_bytes(), &log).unwrap(), heads)
    }

    fn may_seal(
        policy: &GroupPolicyState,
        device: &str,
        seed: u8,
        seq: u64,
        head: [u8; 32],
    ) -> bool {
        PolicyView::Verified(policy).writer_at_policy_point(
            device,
            &fingerprint(seed),
            &SealPolicyPoint { seq, epoch: 0, head },
        )
    }

    /// Authorized writers are trusted for truthful state observation and
    /// completeness, so any device that is a writer under the checkpoint's key
    /// at the policy point may seal (an editor, or the legacy owner value read
    /// as a writer); a viewer never may.
    #[test]
    fn any_writer_may_seal_a_native_checkpoint_and_a_viewer_may_not() {
        let (policy, heads) = policy();
        let at = heads[2];
        assert!(may_seal(&policy, "device-owner", 1, 3, at), "a legacy owner value is a writer");
        assert!(may_seal(&policy, "device-editor", 2, 3, at), "an editor is a writer and may seal");
        assert!(!may_seal(&policy, "device-viewer", 3, 3, at), "a viewer neither writes nor seals");
        assert!(!may_seal(&policy, "device-editor", 9, 3, at), "the grant binds the signing key");
        assert!(!may_seal(&policy, "device-nobody", 1, 3, at), "an unknown device holds nothing");
        // The role is the one the chain held at the point the seal names: the
        // editor was granted at seq 2, so seq 1 does not carry it yet.
        assert!(may_seal(&policy, "device-owner", 1, 1, heads[0]));
        assert!(!may_seal(&policy, "device-editor", 2, 1, heads[0]));
        assert!(may_seal(&policy, "device-editor", 2, 2, heads[1]));
        // Genesis keeps the authority-only rule.
        assert!(may_seal(&policy, "device-any", 5, 0, GENESIS_POLICY_HEAD));
    }

    /// The genesis rule (an authority-only seal at the empty chain) holds only
    /// while the authority has never rotated: afterwards a seal the retired key
    /// signs at the empty chain is not evidence, and no publication checkpoint
    /// pinned there is vouched for either.
    #[test]
    fn the_genesis_rule_closes_after_the_authority_rotates() {
        use crate::change_policy::policy_signing::rotate_record;
        let record = rotate_record(&authority(), GROUP, 1, [0u8; 32], [8u8; 32]);
        let head: [u8; 32] = record.record_hash.as_slice().try_into().unwrap();
        let log = GroupPolicyLog {
            group_id: GROUP.into(),
            current_seq: 1,
            current_epoch: 0,
            policy_head: head.to_vec(),
            records: vec![record],
        };
        let rotated =
            verify_group_policy_log(&authority().verifying_key().to_bytes(), &log).unwrap();
        assert!(
            !may_seal(&rotated, "device-any", 5, 0, GENESIS_POLICY_HEAD),
            "a retired key's seal at the empty chain must not be accepted"
        );
        let point = SealPolicyPoint { seq: 0, epoch: 0, head: GENESIS_POLICY_HEAD };
        assert!(!PolicyView::Verified(&rotated).writer_at_policy_point(
            "device-any",
            &fingerprint(5),
            &point
        ));
    }
}
