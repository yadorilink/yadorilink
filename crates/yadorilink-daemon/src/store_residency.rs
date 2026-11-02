//! Puts the current versions of files into the block store from the files that hold them.
//!
//! A version that capture only hashed (see [`crate::ingest_policy`]) is held by the user's file
//! alone, and so is a version this device received. That is enough until something needs the bytes
//! after the file has moved on: a user's own edit replaces a version nobody promised to keep, but
//! an item the user **pinned**, or a **custody lease** that names the group, promises the version.
//! The promise is met by making the store hold it **now**, while the file still is the version:
//! the file is read, each block is checked against the hash the version lists, and the blocks are
//! put into the store in bounded batches (the group's provenance recorded only after a batch is
//! durable).
//!
//! A file that is no longer the version (it was edited, replaced or removed since its record) is
//! not an answer, and is not refused: it is journaled for capture, and the caller is told the
//! item is not yet in the store. The next capture of it goes into the store (the caller has
//! pinned the item, or asked the group for store-mode captures), after which a second call finds
//! it there. Nothing here loops: a caller that is told to retry decides when.

use std::path::Path;
use std::sync::Arc;

use yadorilink_local_storage::BlockContentStore;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootLease;

use crate::file_block_source::{mark_for_capture, open_source, Opened, MODIFIED, REMOVED};
use crate::local_convergence::version_retention::{
    ingest_version_from_file, version_kept_in_store, IngestError, IngestOutcome,
};
use crate::replica_coordinator::ReplicaCoordinator;
use crate::sync_error::SyncError;

/// Whether the current versions asked about are in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Residency {
    /// Every current version beneath the prefix that this device holds as bytes is in the store.
    InStore,
    /// These paths are not (yet): each is journaled for capture, which puts its next version into
    /// the store, or could not be read as a source right now. Ask again later.
    Pending(Vec<String>),
}

/// [`bring_current_versions_into_store_with`] for the daemon: the folder, the root lease and the store
/// are the ones the group's link runs with.
pub(crate) async fn bring_current_versions_into_daemon_store(
    state: &crate::daemon_state::DaemonState,
    group_id: &str,
    prefix: &str,
) -> Result<Residency, SyncError> {
    bring_current_versions_into_daemon_store_with(state, group_id, prefix, true).await
}

/// [`bring_current_versions_into_daemon_store`] that, with `wait` false, leaves a path whose lock
/// is held pending instead of waiting for it.
pub(crate) async fn bring_current_versions_into_daemon_store_with(
    state: &crate::daemon_state::DaemonState,
    group_id: &str,
    prefix: &str,
    wait: bool,
) -> Result<Residency, SyncError> {
    // Nothing to read means no folder is needed: a group without files has nothing to bring in.
    if state
        .replica_coordinator
        .file_index_repository()
        .list_live_files_under(group_id, prefix)?
        .is_empty()
        && prefix.is_empty()
    {
        return Ok(Residency::InStore);
    }
    let store: Arc<dyn BlockContentStore + Send + Sync> = Arc::new(
        crate::adapters::block_store_ports::BlockStorePortsAdapter::new(state.block_store.clone()),
    );
    // The folder and its root lease are looked up only when a file has to be read: a device whose
    // folder is unmounted, or whose link is not (yet) watching, still answers for every version
    // it already holds in the store, and fails only for the ones it would have to read.
    bring_current_versions_into_store_with(
        &state.replica_coordinator,
        &store,
        &|| {
            Ok((
                crate::hydration::local_root_for_group(state, group_id)?,
                state.root_lease_for(group_id)?,
            ))
        },
        group_id,
        prefix,
        wait,
    )
    .await
}

/// Journals `path` for capture and reports it not yet in the store. A journal that cannot be
/// written is an error, not a pending path: nothing would then bring the path's next version into
/// the store, and a caller told to ask again would wait for nothing.
fn journal(
    coordinator: &ReplicaCoordinator,
    lease: &RootLease,
    group_id: &str,
    path: &str,
    kind: &str,
) -> Result<Settled, SyncError> {
    if mark_for_capture(coordinator, lease, group_id, path, kind) {
        Ok(Settled::NotYet)
    } else {
        Err(SyncError::HydrationFailed(format!(
            "{path}: it is not the version on record and could not be journaled for capture"
        )))
    }
}

/// What became of one path.
enum Settled {
    /// In the store (now, or already), or not held as bytes on this device at all.
    Done,
    /// Not in the store, and not readable as the version now.
    NotYet,
    /// Not in the store, and the folder it would be read from has not been looked up yet.
    NeedsFolder,
}

/// The folder a file is read from and the lease its capture journal is written under.
type Folder = (std::path::PathBuf, Arc<RootLease>);

/// Brings every live current file at or beneath `prefix` of `group_id` (`""` is the whole group)
/// into the store, reading it from the folder `folder` names where the store lacks it. The folder is
/// looked up the first time a file has to be read, and not at all when the store already holds
/// everything.
/// The same, but with `wait` false it does not wait for the lock of a path someone else holds:
/// such a path is reported pending. For a caller that may itself be running under a path lock.
pub(crate) async fn bring_current_versions_into_store_with(
    coordinator: &Arc<ReplicaCoordinator>,
    store: &Arc<dyn BlockContentStore + Send + Sync>,
    folder: &(dyn Fn() -> Result<Folder, SyncError> + Sync),
    group_id: &str,
    prefix: &str,
    wait: bool,
) -> Result<Residency, SyncError> {
    let repository = coordinator.file_index_repository();
    let mut paths = repository.list_live_files_under(group_id, prefix)?;
    if !prefix.is_empty() {
        let is_live_file =
            repository.get_file(group_id, prefix)?.is_some_and(|record| !record.deleted)
                && repository.get_record_kind(group_id, prefix)?
                    == Some(yadorilink_replica_domain::file::RecordKind::File);
        if is_live_file {
            paths.push(prefix.to_owned());
        }
    }
    paths.sort();
    paths.dedup();
    let mut pending = Vec::new();
    let mut resolved: Option<Folder> = None;
    for path in paths {
        // The path's lock keeps a capture or a receive from replacing the file while it is read.
        let lock = coordinator.path_lock_registry().path_lock(group_id, &path);
        let _held = if wait {
            lock.lock_owned().await
        } else {
            match lock.try_lock_owned() {
                Ok(held) => held,
                Err(_) => {
                    pending.push(path);
                    continue;
                }
            }
        };
        let mut settled =
            settle_blocking(coordinator, store, resolved.as_ref(), group_id, &path).await?;
        if matches!(settled, Settled::NeedsFolder) {
            resolved = Some(folder()?);
            settled =
                settle_blocking(coordinator, store, resolved.as_ref(), group_id, &path).await?;
        }
        if matches!(settled, Settled::NotYet) {
            pending.push(path);
        }
    }
    Ok(if pending.is_empty() { Residency::InStore } else { Residency::Pending(pending) })
}

async fn settle_blocking(
    coordinator: &Arc<ReplicaCoordinator>,
    store: &Arc<dyn BlockContentStore + Send + Sync>,
    folder: Option<&Folder>,
    group_id: &str,
    path: &str,
) -> Result<Settled, SyncError> {
    let (coordinator, store) = (coordinator.clone(), store.clone());
    let folder = folder.cloned();
    let (group, file_path) = (group_id.to_owned(), path.to_owned());
    tokio::task::spawn_blocking(move || {
        let folder = folder.as_ref().map(|(root, lease)| (root.as_path(), lease.as_ref()));
        settle_one(&coordinator, &store, folder, &group, &file_path)
    })
    .await
    .map_err(|error| SyncError::HydrationFailed(format!("store residency task: {error}")))?
}

fn settle_one(
    coordinator: &Arc<ReplicaCoordinator>,
    store: &Arc<dyn BlockContentStore + Send + Sync>,
    folder: Option<(&Path, &RootLease)>,
    group_id: &str,
    path: &str,
) -> Result<Settled, SyncError> {
    let Some(record) = coordinator.file_index_repository().get_file(group_id, path)? else {
        return Ok(Settled::Done);
    };
    if record.deleted || record.blocks.is_empty() {
        return Ok(Settled::Done);
    }
    // Only a placeholder holds no bytes of this version here. A file being made or removed is on
    // its way to holding them (or to losing them): it is not settled, and a receive that finishes
    // after this pass would leave the version with the file alone. A row that says nothing is not
    // assumed to be a placeholder.
    match coordinator
        .materialization_state_repository()
        .get_materialization_state(group_id, path)?
    {
        Some(MaterializationState::Remote) => return Ok(Settled::Done),
        Some(MaterializationState::Present) => {}
        Some(MaterializationState::Hydrating | MaterializationState::Evicting) | None => {
            return Ok(Settled::NotYet);
        }
    }
    let provenance =
        |hashes: &[Vec<u8>]| coordinator.group_has_block_provenance_batch(group_id, hashes);
    let kept = version_kept_in_store(store.as_ref(), &provenance, &record.blocks)
        .map_err(|error| SyncError::HydrationFailed(format!("{path}: {error:?}")))?;
    if kept {
        return Ok(Settled::Done);
    }
    let Some((root, lease)) = folder else {
        return Ok(Settled::NeedsFolder);
    };
    let Ok(resolved) =
        yadorilink_local_storage::resolve_read_path_without_traversal(root, Path::new(path))
    else {
        return Ok(Settled::NotYet);
    };
    let file = match open_source(&resolved) {
        Opened::File(file) => file,
        // Nothing wrong with the file, only not readable as a source now.
        Opened::Unavailable => return Ok(Settled::NotYet),
        Opened::Gone => return journal(coordinator, lease, group_id, path, REMOVED),
    };
    let record_provenance =
        |hashes: &[Vec<u8>]| coordinator.record_retained_blocks_provenance(group_id, hashes);
    match ingest_version_from_file(store.as_ref(), &file, &record.blocks, &record_provenance) {
        Ok(IngestOutcome::Ingested) => Ok(Settled::Done),
        Ok(IngestOutcome::NotTheVersion) => journal(coordinator, lease, group_id, path, MODIFIED),
        Err(IngestError::Read(_)) => Ok(Settled::NotYet),
        Err(error) => Err(SyncError::HydrationFailed(format!("{path}: {error:?}"))),
    }
}

/// Puts the version `blocks` lists into the store from `file_path` unless it already is there,
/// for [`yadorilink_replica_engine::custody::FullReplicaCustody::ensure_version_in_store`] and the
/// custody responder's `ensure_version_in_store`. The caller holds the block store's
/// reference-write guard; the blocks are checked against their hashes as they are read, so a file
/// replaced meanwhile is never taken for the version (it is reported as not being it).
pub(crate) fn ensure_file_in_store(
    coordinator: &ReplicaCoordinator,
    store: &dyn BlockContentStore,
    group_id: &str,
    path: &str,
    file_path: &Path,
    blocks: &[yadorilink_replica_domain::file::BlockInfo],
) -> yadorilink_replica_engine::custody::StoreResidency {
    use yadorilink_replica_engine::custody::StoreResidency;
    if blocks.is_empty() {
        return StoreResidency::InStore;
    }
    let provenance =
        |hashes: &[Vec<u8>]| coordinator.group_has_block_provenance_batch(group_id, hashes);
    match version_kept_in_store(store, &provenance, blocks) {
        Ok(true) => return StoreResidency::InStore,
        Ok(false) => {}
        Err(error) => return StoreResidency::Failed(format!("{error:?}")),
    }
    let file = match open_source(file_path) {
        Opened::File(file) => file,
        Opened::Gone => return StoreResidency::NotTheVersion,
        Opened::Unavailable => {
            return StoreResidency::Failed(format!("{path} cannot be read right now"));
        }
    };
    let record_provenance =
        |hashes: &[Vec<u8>]| coordinator.record_retained_blocks_provenance(group_id, hashes);
    match ingest_version_from_file(store, &file, blocks, &record_provenance) {
        Ok(IngestOutcome::Ingested) => StoreResidency::InStore,
        Ok(IngestOutcome::NotTheVersion) => StoreResidency::NotTheVersion,
        Err(error) => StoreResidency::Failed(format!("{error:?}")),
    }
}
