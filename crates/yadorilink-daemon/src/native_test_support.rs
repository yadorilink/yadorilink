//! Shared fixtures for the native replication tests: a device's local native
//! deltas and a fake coordination plane that issues real signed checkpoints.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use ed25519_dalek::{SigningKey, VerifyingKey};
use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::authorization_checkpoint::{
    fingerprint_signing_key, sign_checkpoint, AuthorizationCheckpoint,
};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, NativeDelta};
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::native_store;

use crate::checkpoint_source::CheckpointSource;

pub(crate) const GROUP: &str = "g";
pub(crate) const DEVICE: &str = "device-A";

pub(crate) fn db() -> SyncDatabase {
    SyncDatabase::open_in_memory(|conn| {
        yadorilink_sync_sqlite::replica_tables::init_for_tests(conn)
            .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))
    })
    .unwrap()
}

pub(crate) fn device_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

pub(crate) fn device_vk() -> VerifyingKey {
    device_key().verifying_key()
}

/// Installs the next delta of `DEVICE`'s incarnation `incarnation`.
pub(crate) fn author_delta(c: &SyncDatabase, incarnation: u8, path: &str) -> NativeDelta {
    let author =
        AuthorId { device: DeviceId(DEVICE.into()), incarnation: IncarnationId([incarnation; 16]) };
    let group = FolderGroupId(GROUP.into());
    c.write(|conn| {
        let entry = native_store::frontier_entry_get(conn, &group, &author)?;
        let (seq, prev) = match entry {
            None => (AuthorSeq::FIRST, None),
            Some(entry) => (entry.seq.checked_next().unwrap(), Some(entry.tip)),
        };
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group.clone(),
            author: author.clone(),
            seq,
            prev,
            ops: vec![DeltaOp {
                path: SyncPath(path.into()),
                removes: Vec::new(),
                put: Some(DeltaPut { version: VersionHash([path.len() as u8; 32]) }),
            }],
            signature: [0; 64],
        };
        delta.sign(&device_key());
        native_store::install_verified_delta(conn, &group, &delta, &device_vk())?;
        Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(delta)
    })
    .unwrap()
}

pub(crate) struct FakeSource {
    pub(crate) authority_key: SigningKey,
    pub(crate) signer_key_id: [u8; 32],
    pub(crate) next_seq: Mutex<u64>,
    pub(crate) refuse: bool,
}

impl FakeSource {
    pub(crate) fn new() -> Self {
        Self {
            authority_key: SigningKey::from_bytes(&[7u8; 32]),
            signer_key_id: [0u8; 32],
            next_seq: Mutex::new(0),
            refuse: false,
        }
    }
}

pub(crate) fn resolver_for(
    source: &FakeSource,
) -> impl Fn(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey> + '_ {
    let signer_key_id = source.signer_key_id;
    let vk = source.authority_key.verifying_key();
    move |key_id: &[u8; 32], _head: &[u8; 32]| (*key_id == signer_key_id).then_some(vk)
}

impl CheckpointSource for FakeSource {
    fn request_authorization_checkpoint<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        _request_id: &'a str,
        merkle_root: [u8; 32],
        leaf_count: u64,
        _purpose: crate::checkpoint_source::CheckpointPurpose,
    ) -> Pin<Box<dyn Future<Output = Option<(AuthorizationCheckpoint, [u8; 64])>> + Send + 'a>>
    {
        Box::pin(async move {
            if self.refuse {
                return None;
            }
            let mut seq = self.next_seq.lock().unwrap();
            *seq += 1;
            let checkpoint = AuthorizationCheckpoint {
                group_id: group_id.to_string(),
                device_id: device_id.to_string(),
                signing_key_fingerprint: fingerprint_signing_key(&device_vk()),
                merkle_root,
                leaf_count,
                checkpoint_seq: *seq,
                signer_key_id: self.signer_key_id,
                policy_epoch: 0,
                policy_seq: 1,
                policy_head: [0u8; 32],
                issued_at_unix: 1,
            };
            let signature = sign_checkpoint(&checkpoint, &self.authority_key);
            Some((checkpoint, signature))
        })
    }
}
