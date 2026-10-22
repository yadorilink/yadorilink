//! Evict, download and status for a directory as a whole.
//!
//! A directory has no bytes of its own, so what a user asks of it acts on
//! the files below it. Evicting a directory frees every hydrated file below
//! it. Downloading hydrates every file below it.
//!
//! All of this is local projection: nothing here authors a change or alters
//! what the folder's history says.

use std::sync::Arc;

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_sync_sqlite::pinned_items::path_is_covered;
use yadorilink_sync_sqlite::RetentionPolicy;

use crate::daemon_state::DaemonState;
use crate::sync_error::SyncError;

use super::MaterializationStatusInfo;

/// Whether `path` names a directory of the link: the link root (`""`), a
/// live explicit directory entry, or a path with live entries below it.
pub(crate) fn is_indexed_directory(
    state: &DaemonState,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncError> {
    if path.is_empty() {
        return Ok(true);
    }
    let index = state.replica_coordinator.file_index_repository();
    let live_row = index.get_file(group_id, path)?.is_some_and(|row| !row.deleted);
    if live_row {
        return Ok(index.get_record_kind(group_id, path)? == Some(RecordKind::Directory));
    }
    Ok(index.has_live_descendant_row(group_id, path)?)
}

/// What evicting a directory freed.
#[derive(Debug)]
pub(crate) struct DirectoryEviction {
    pub(crate) evicted_files: u64,
    pub(crate) blocks_reclaimed: u64,
    pub(crate) bytes_reclaimed: u64,
}

/// Frees every hydrated file below the directory `prefix`.
pub(crate) fn evict_directory(
    state: &DaemonState,
    group_id: &str,
    prefix: &str,
) -> Result<DirectoryEviction, SyncError> {
    crate::hydration::evict_gate(state, group_id, prefix)?;
    let pins = state.replica_coordinator.pinned_item_repository();
    // A folder that is itself kept is refused as a whole; a folder that merely holds kept files
    // is freed around them.
    if pins.retention(group_id, prefix)?.policy == RetentionPolicy::Pinned {
        return Err(SyncError::EvictionRejected(format!(
            "{}: kept on this device; stop keeping it first to free up its space",
            if prefix.is_empty() { "root" } else { prefix }
        )));
    }
    let pinned_below = pins.pinned_beneath(group_id, prefix)?;
    let index = state.replica_coordinator.file_index_repository();
    let materialization = state.replica_coordinator.materialization_state_repository();
    let mut attempts = Vec::new();
    for path in index.list_live_files_under(group_id, prefix)? {
        if materialization.get_materialization_state(group_id, &path)?
            != Some(MaterializationState::Present)
            || path_is_covered(&pinned_below, &path)
        {
            continue;
        }
        let attempt = super::evict(state, group_id, &path).map(|evicted| FileEviction {
            dehydrated: evicted.dehydrated,
            blocks_reclaimed: evicted.blocks_reclaimed,
            bytes_reclaimed: evicted.bytes_reclaimed,
        });
        if let Err(error) = &attempt {
            tracing::debug!(%error, group_id, path = %path, "a file below an evicted directory stayed");
        }
        attempts.push((path, attempt));
    }
    fold_directory_eviction(prefix, attempts)
}

/// One file's eviction, as [`fold_directory_eviction`] reads it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FileEviction {
    pub(crate) dehydrated: bool,
    pub(crate) blocks_reclaimed: u64,
    pub(crate) bytes_reclaimed: u64,
}

/// Sums the evictions of the files below `prefix`. When every file that
/// could have been freed was, or none was and none failed (each left as it
/// was, the way a single busy file's eviction reports), the sum is the
/// outcome. Otherwise the folder was only partly freed, and that is an
/// error naming how many files stayed and why the first did -- never a
/// plain success. A failure with nothing freed is that file's own error.
pub(crate) fn fold_directory_eviction(
    prefix: &str,
    attempts: Vec<(String, Result<FileEviction, SyncError>)>,
) -> Result<DirectoryEviction, SyncError> {
    let eligible = attempts.len();
    let mut outcome =
        DirectoryEviction { evicted_files: 0, blocks_reclaimed: 0, bytes_reclaimed: 0 };
    let mut stayed = Vec::new();
    let mut first_error = None;
    for (path, attempt) in attempts {
        match attempt {
            Ok(evicted) => {
                if evicted.dehydrated {
                    outcome.evicted_files += 1;
                } else {
                    stayed.push(path);
                }
                outcome.blocks_reclaimed += evicted.blocks_reclaimed;
                outcome.bytes_reclaimed += evicted.bytes_reclaimed;
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some((path.clone(), error));
                }
                stayed.push(path);
            }
        }
    }
    match first_error {
        None if outcome.evicted_files == 0 || stayed.is_empty() => Ok(outcome),
        Some((_, error)) if outcome.evicted_files == 0 => Err(error),
        first_error => {
            let folder = if prefix.is_empty() { "root" } else { prefix };
            let reason = match first_error {
                Some((path, error)) => format!("{path}: {error}"),
                None => format!("{} was busy or changed while being freed", stayed[0]),
            };
            Err(SyncError::EvictionRejected(format!(
                "{folder}: {} of {eligible} files stayed on this device ({} freed, {} bytes); \
                 first: {reason}",
                stayed.len(),
                outcome.evicted_files,
                outcome.bytes_reclaimed,
            )))
        }
    }
}

/// Fetches every file below the directory `prefix` that is not here yet.
/// Every file is attempted; the first failure is reported after.
pub(crate) async fn hydrate_directory(
    state: &Arc<DaemonState>,
    group_id: &str,
    prefix: &str,
) -> Result<(), SyncError> {
    let mut first_error = None;
    for path in files_not_hydrated_under(state, group_id, prefix)? {
        if let Err(error) = super::hydrate(state, group_id, &path).await {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Hydrates every live file below the directory `prefix`, including the ones already here (a
/// no-op for those, decided under each file's own lock). Every file is attempted; the first
/// failure is reported after.
pub(crate) async fn hydrate_every_file(
    state: &Arc<DaemonState>,
    group_id: &str,
    prefix: &str,
) -> Result<(), SyncError> {
    let mut first_error = None;
    for path in
        state.replica_coordinator.file_index_repository().list_live_files_under(group_id, prefix)?
    {
        if let Err(error) = super::hydrate(state, group_id, &path).await {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// A directory's materialization state, from the files below it.
pub(crate) fn directory_status(
    state: &DaemonState,
    group_id: &str,
    prefix: &str,
) -> Result<MaterializationStatusInfo, SyncError> {
    Ok(MaterializationStatusInfo {
        state: state
            .replica_coordinator
            .materialization_state_repository()
            .directory_materialization_state(group_id, prefix)?,
    })
}

fn files_not_hydrated_under(
    state: &DaemonState,
    group_id: &str,
    prefix: &str,
) -> Result<Vec<String>, SyncError> {
    let materialization = state.replica_coordinator.materialization_state_repository();
    let mut out = Vec::new();
    for path in
        state.replica_coordinator.file_index_repository().list_live_files_under(group_id, prefix)?
    {
        // `Present` says only that an object exists: it is hydrated only
        // where a usable proof names the version the row holds now.
        if materialization.get_materialization_state(group_id, &path)?
            != Some(MaterializationState::Present)
            || !state.replica_coordinator.local_copy_names_current_version(group_id, &path)?
        {
            out.push(path);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
