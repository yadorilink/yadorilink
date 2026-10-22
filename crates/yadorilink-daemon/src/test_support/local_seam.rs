//! Local authoring for tests through the production local-capture seam.
//!
//! A test that needs "this device saved `path`" or "this device deleted
//! `path`" commits through [`LocalMutationStore::commit_local_mutations_batch`]
//! on the [`ReplicaCoordinator`], the port method the watcher's flush
//! drives. That method routes through the `local_commit` alias, so the
//! test authors whatever production authors, with the capture's native
//! witness read from the current row exactly as capture reads it.
//!
//! The author handle must come from [`replica_author_key`]: authoring
//! refuses a handle whose incarnation is not the replica's current one
//! (`StaleAuthor`).

use ed25519_dalek::SigningKey;
use yadorilink_local_capture::ports::{LocalChangeEmission, LocalMutationStore};
use yadorilink_replica_domain::file::{FileRecord, FileVersion};
use yadorilink_replica_domain::ids::{DeviceId, SyncPath};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::author_incarnation::{self, IncarnationEnvironment};
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;
use yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence;
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::replica_coordinator::ReplicaCoordinator;

/// The author handle `device_id` signs its local writes on `coordinator`'s
/// replica with: the replica's current author incarnation, minted
/// (`Install`) when the replica has none yet. Refused when the replica's
/// incarnation belongs to another device, since authoring
/// would refuse that handle as stale.
pub fn replica_author_key(
    coordinator: &ReplicaCoordinator,
    device_id: &str,
    signing_key: SigningKey,
) -> Result<LocalAuthorKey, SyncSqliteError> {
    let record =
        coordinator.database().write(|conn| {
            match author_incarnation::incarnation_record(conn)? {
                Some(record) => Ok(record),
                None => author_incarnation::ensure_incarnation(
                    conn,
                    &IncarnationEnvironment {
                        device_id: DeviceId(device_id.to_owned()),
                        sidecar: None,
                        machine_fingerprint: Vec::new(),
                    },
                ),
            }
        })?;
    if record.author.device.as_str() != device_id {
        return Err(SyncSqliteError::CorruptState(format!(
            "the replica's author incarnation belongs to {}, not {device_id}",
            record.author.device.as_str()
        )));
    }
    Ok(LocalAuthorKey::new(record.author, signing_key))
}

/// Saves `version` at `record.path` as one local write: a `Put` of the
/// version over the head the current row shows. `meta` are the local
/// metadata columns committed with the row.
// One argument per part of the saved file.
#[allow(clippy::too_many_arguments)]
pub fn commit_local_upsert(
    coordinator: &ReplicaCoordinator,
    group_id: &str,
    record: &FileRecord,
    origin_device_id: &str,
    version: &FileVersion,
    meta: Option<LocalFileMetaColumns>,
    author: &LocalAuthorKey,
    permit: &RootCommitPermit<'_>,
) -> Result<(), SyncSqliteError> {
    let op = Op::Put { path: SyncPath(record.path.clone()), version: version.version_hash };
    let mutation = PreparedLocalMutation::Upsert {
        record: record.clone(),
        op,
        version: version.clone(),
        meta,
        native_witness: Some(
            coordinator.file_index_repository().native_capture_witness(group_id, &record.path)?,
        ),
    };
    coordinator.commit_local_mutations_batch(
        group_id,
        std::slice::from_ref(&mutation),
        &[],
        origin_device_id,
        LocalChangeEmission { author, permit },
    )
}

/// Deletes `path` as one local write observed at `observed_at_unix_nanos`:
/// a `Delete` over the head the current row shows. With
/// `absent_evidence` the tombstone commits the observed absence as the
/// path's actual state (capture's `Absent` evidence).
// One argument per part of the observed deletion.
#[allow(clippy::too_many_arguments)]
pub fn commit_local_delete(
    coordinator: &ReplicaCoordinator,
    group_id: &str,
    path: &str,
    origin_device_id: &str,
    observed_at_unix_nanos: i64,
    absent_evidence: bool,
    author: &LocalAuthorKey,
    permit: &RootCommitPermit<'_>,
) -> Result<(), SyncSqliteError> {
    let row = coordinator.canonical_current_row(group_id, path)?.ok_or_else(|| {
        SyncSqliteError::CorruptState(format!("no current row to delete at {path}"))
    })?;
    let record = FileRecord {
        path: path.to_owned(),
        size: row.snapshot.size,
        mtime_unix_nanos: observed_at_unix_nanos,
        blocks: row.snapshot.blocks.clone(),
        deleted: true,
    };
    let mutation = PreparedLocalMutation::Delete {
        record,
        op: Op::Delete { path: SyncPath(path.to_owned()) },
        native_witness: Some(
            coordinator.file_index_repository().native_capture_witness(group_id, path)?,
        ),
    };
    let evidence = [absent_evidence.then_some(LocalCaptureActualStateEvidence::Absent)];
    coordinator.commit_local_mutations_batch(
        group_id,
        std::slice::from_ref(&mutation),
        &evidence,
        origin_device_id,
        LocalChangeEmission { author, permit },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The handle names the replica's current author, so
    /// authoring accepts it, and it stays the same author on every call.
    #[test]
    fn the_author_key_names_the_replicas_current_incarnation() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let key =
            replica_author_key(&coordinator, "device-a", SigningKey::from_bytes(&[3; 32])).unwrap();
        let current = coordinator.database().read(author_incarnation::current_author).unwrap();
        assert_eq!(key.author(), current.clone());
        let again =
            replica_author_key(&coordinator, "device-a", SigningKey::from_bytes(&[3; 32])).unwrap();
        assert_eq!(again.author(), current);
        assert!(
            replica_author_key(&coordinator, "device-b", SigningKey::from_bytes(&[3; 32])).is_err()
        );
    }
}
