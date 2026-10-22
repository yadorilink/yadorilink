//! Keep this / Keep both for a conflict copy, decided and performed here.
//!
//! A front end only names the copy and the choice. What the list showed a
//! moment ago is not trusted: every precondition is read again while the
//! action runs, and the action is refused, with nothing changed, when it no
//! longer holds.
//!
//! * Keep this writes the copy's recorded content at the original name through
//!   the guarded restore write ([`hydration::restore_content_with_timeout`]):
//!   it refuses while the original holds bytes, a mode or attributes that are
//!   not its recorded version (an edit capture has not taken yet), looks at the
//!   disk again right before the replacing rename, and authors the result as a
//!   new version, so the version it replaces stays in the file's history. The
//!   copy is left exactly as it is, under its own name: it is never moved,
//!   renamed or deleted, so nothing can be lost from it, and it stays listed
//!   as a conflict copy until it is removed by hand.
//! * Keep both moves the copy to the first free `name (other version N).ext`
//!   with a no-replace move. A name taken in the meantime is never overwritten:
//!   the move fails and the next name is tried.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use yadorilink_fs_platform::durable_dir::{self, Replace};
use yadorilink_replica_domain::conflict::{
    conflict_copy_source_path, conflict_copy_stem_was_truncated,
};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::VersionState;
use yadorilink_sync_sqlite::restore_operation::RestorePlacement;

pub(crate) use crate::application::ports::version_restore::{ConflictChoice, ResolveConflictError};
use crate::daemon_state::DaemonState;
use crate::hydration::{self, RestoreSource};
use crate::replica_coordinator::ReplicaCoordinator;
use crate::sync_error::SyncError;

impl From<yadorilink_sync_sqlite::SyncSqliteError> for ResolveConflictError {
    fn from(error: yadorilink_sync_sqlite::SyncSqliteError) -> Self {
        ResolveConflictError::Failed(error.into())
    }
}

impl From<yadorilink_root_authority::RootAuthorityError> for ResolveConflictError {
    fn from(error: yadorilink_root_authority::RootAuthorityError) -> Self {
        ResolveConflictError::Failed(error.into())
    }
}

/// Why a conflict copy is kept under its own name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConflictCopyReason {
    /// Concurrent changes to the same path; the copy holds a version that
    /// did not win it.
    ConcurrentEdit,
    /// The path the copy came from is a folder now -- a live explicit
    /// directory, or a path with live entries below it -- so the file or
    /// link was moved aside rather than replace it.
    FolderAtPath,
}

/// Read from what the copy's source path is now: a folder there (its own
/// live Directory row, or any live row below it) is why the copy cannot take
/// that name; otherwise it lost the path to a concurrent version.
pub(crate) fn conflict_copy_reason(
    coordinator: &ReplicaCoordinator,
    group_id: &str,
    copy_path: &str,
) -> Result<ConflictCopyReason, SyncError> {
    let source = conflict_copy_source_path(copy_path);
    let index = coordinator.file_index_repository();
    let source_is_directory = index.get_file(group_id, &source)?.is_some_and(|row| !row.deleted)
        && index.get_record_kind(group_id, &source)? == Some(RecordKind::Directory);
    if source_is_directory || index.has_live_descendant_row(group_id, &source)? {
        return Ok(ConflictCopyReason::FolderAtPath);
    }
    Ok(ConflictCopyReason::ConcurrentEdit)
}

/// Whether Keep this / Keep both is offered for a listed copy. The one
/// predicate both the list and [`resolve_conflict`] use: a file copy of a
/// concurrent edit whose original name is known exactly.
pub(crate) fn conflict_copy_resolvable(
    copy_path: &str,
    record_kind: RecordKind,
    reason: ConflictCopyReason,
) -> bool {
    record_kind == RecordKind::File
        && reason == ConflictCopyReason::ConcurrentEdit
        && !conflict_copy_stem_was_truncated(copy_path)
        && conflict_copy_source_path(copy_path) != copy_path
}

/// Resolves the conflict copy at `copy_path` (relative to the group's root) and
/// returns the absolute path that holds its content afterwards.
pub(crate) async fn resolve_conflict(
    state: &Arc<DaemonState>,
    group_id: &str,
    copy_path: &str,
    choice: ConflictChoice,
) -> Result<PathBuf, ResolveConflictError> {
    let coordinator = state.replica_coordinator.as_ref();
    let Some(copy) = coordinator
        .file_index_repository()
        .list_live_conflict_copies(group_id)?
        .into_iter()
        .find(|copy| copy.path == copy_path)
    else {
        return Err(ResolveConflictError::NotAConflictCopy(copy_path.to_string()));
    };
    let reason = conflict_copy_reason(coordinator, group_id, copy_path)?;
    if !conflict_copy_resolvable(copy_path, copy.record_kind, reason) {
        return Err(ResolveConflictError::NotResolvable(match reason {
            ConflictCopyReason::FolderAtPath => "the original name is a folder now".into(),
            ConflictCopyReason::ConcurrentEdit => {
                "it is not a file with a known original name".into()
            }
        }));
    }
    let root = hydration::local_root_for_group(state, group_id)?;
    let copy_abs = root.join(copy_path);
    copy_in_place(state, group_id, &root, &copy_abs)?;
    let original = conflict_copy_source_path(copy_path);
    match choice {
        ConflictChoice::KeepThis => {
            keep_this(state, group_id, &root, copy_path, &copy_abs, &original).await
        }
        ConflictChoice::KeepBoth => {
            keep_both(state, group_id, &root, copy_path, &copy_abs, &original).await
        }
    }
}

/// The copy may be moved (Keep both) or read from: the group is not frozen by a rebootstrap,
/// no folder above the copy is a link out of the root (Keep both's target
/// shares the copy's folder, so this covers it too), and the copy is a file.
/// Asked again under the copy's path lock right before each mutation.
fn copy_in_place(
    state: &Arc<DaemonState>,
    group_id: &str,
    root: &Path,
    copy_abs: &Path,
) -> Result<(), ResolveConflictError> {
    if state.replica_coordinator.held_path_repository().group_frozen(group_id)? {
        return Err(ResolveConflictError::Failed(SyncError::HydrationFailed(format!(
            "{group_id} is frozen by a rebootstrap"
        ))));
    }
    // Read-only: the copy's folder resolved through any links must still be
    // inside the root resolved the same way. Nothing is created here.
    let inside = match (copy_abs.parent().map(std::fs::canonicalize), std::fs::canonicalize(root)) {
        (Some(Ok(parent)), Ok(root)) => parent.starts_with(root),
        _ => false,
    };
    if !inside {
        return Err(ResolveConflictError::NotResolvable(
            "the copy is not inside the folder".into(),
        ));
    }
    if !std::fs::symlink_metadata(copy_abs).is_ok_and(|meta| meta.is_file()) {
        return Err(ResolveConflictError::NotResolvable("the copy is no longer a file".into()));
    }
    Ok(())
}

async fn keep_this(
    state: &Arc<DaemonState>,
    group_id: &str,
    root: &Path,
    copy_path: &str,
    copy_abs: &Path,
    original: &str,
) -> Result<PathBuf, ResolveConflictError> {
    let original_abs = root.join(original);
    if std::fs::symlink_metadata(&original_abs).is_ok_and(|meta| meta.is_dir()) {
        return Err(ResolveConflictError::NotResolvable(
            "the original name is a folder now".into(),
        ));
    }
    // The content written is the copy's recorded version, so the copy on disk
    // must be exactly that: what is restored must be what the copy holds.
    {
        let lock = state.replica_coordinator.path_lock_registry().path_lock(group_id, copy_path);
        let _guard = crate::receive_diag::lock_path(&lock).await;
        if !copy_is_recorded(state, group_id, copy_path, copy_abs)? {
            return Err(ResolveConflictError::UnrecordedLocalChanges(copy_path.to_string()));
        }
    }
    let Some(content) = state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(group_id, copy_path)?
        .into_iter()
        .find(|version| version.state == VersionState::Current && !version.deleted)
    else {
        return Err(ResolveConflictError::NotAConflictCopy(copy_path.to_string()));
    };
    let placement = match hydration::restore_content_with_timeout(
        state,
        group_id,
        original,
        RestoreSource::Content(&content),
        hydration::HYDRATION_TIMEOUT,
    )
    .await
    {
        Ok(placement) => placement,
        Err(SyncError::PathChangedLocally(_)) => {
            return Err(ResolveConflictError::UnrecordedLocalChanges(original.to_string()))
        }
        Err(error) => return Err(error.into()),
    };
    // The namespace placed the content somewhere other than the original name
    // (the tree changed shape meanwhile): the copy is what holds the content.
    if placement == RestorePlacement::Projection {
        return Ok(copy_abs.to_path_buf());
    }
    // The copy is not touched: it stays under its own name, with its content,
    // permissions and attributes, and is still listed as a conflict copy.
    Ok(original_abs)
}

/// Whether the copy holds exactly its recorded version and no capture is owed
/// for it.
fn copy_is_recorded(
    state: &Arc<DaemonState>,
    group_id: &str,
    copy_path: &str,
    copy_abs: &Path,
) -> Result<bool, ResolveConflictError> {
    let baseline = hydration::disk_identity(copy_abs)?;
    let dirty =
        state.replica_coordinator.dirty_path_repository().is_path_dirty(group_id, copy_path)?;
    let unrecorded = state
        .local_convergence()
        .removal_would_destroy_unrecorded_state(group_id, copy_path, copy_abs)
        .map_err(|error| SyncError::CorruptState(error.to_string()))?;
    Ok(!dirty && !unrecorded && baseline.is_some())
}

async fn keep_both(
    state: &Arc<DaemonState>,
    group_id: &str,
    root: &Path,
    copy_path: &str,
    copy_abs: &Path,
    original: &str,
) -> Result<PathBuf, ResolveConflictError> {
    let lock = state.replica_coordinator.path_lock_registry().path_lock(group_id, copy_path);
    let _guard = crate::receive_diag::lock_path(&lock).await;
    let root_lease = state.root_lease_for(group_id)?;
    let root_op = root_lease.begin_operation()?;
    let permit = root_op.permit();
    for n in 1u32.. {
        let target = other_version_path(original, n);
        let target_abs = root.join(&target);
        let target_lock =
            state.replica_coordinator.path_lock_registry().path_lock(group_id, &target);
        let _target_guard = crate::receive_diag::lock_path(&target_lock).await;
        // Every check after the last wait, immediately before the move.
        yadorilink_root_authority::root_identity::VerifiedRoot::verify(
            root,
            group_id,
            state.replica_coordinator.as_ref(),
        )?;
        permit.verify()?;
        copy_in_place(state, group_id, root, copy_abs)?;
        bump_fence(state, group_id, copy_path)?;
        bump_fence(state, group_id, &target)?;
        match durable_dir::move_durably(copy_abs, &target_abs, Replace::No) {
            Ok(()) => {
                let coordinator = &state.replica_coordinator;
                coordinator.journal_uncaptured_local_edit(group_id, copy_path, false, &permit)?;
                coordinator.journal_uncaptured_local_edit(group_id, &target, true, &permit)?;
                return Ok(target_abs);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(SyncError::from(error).into()),
        }
    }
    unreachable!("the name counter does not run out before a free name")
}

fn bump_fence(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
) -> Result<(), ResolveConflictError> {
    state.replica_coordinator.begin_path_disk_write(group_id, path, "conflict_resolution").map_err(
        |e| SyncError::CorruptState(format!("{path}: mutation fence bump failed: {e}")).into(),
    )
}

/// `dir/name (other version).ext` for `n == 1`, then `name (other version N).ext`.
pub(crate) fn other_version_path(original: &str, n: u32) -> String {
    let (dir, file) = match original.rsplit_once('/') {
        Some((dir, file)) => (Some(dir), file),
        None => (None, original),
    };
    let (stem, ext) = match file.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (file, None),
    };
    let label = if n == 1 { "other version".to_string() } else { format!("other version {n}") };
    let name = match ext {
        Some(ext) => format!("{stem} ({label}).{ext}"),
        None => format!("{stem} ({label})"),
    };
    match dir {
        Some(dir) => format!("{dir}/{name}"),
        None => name,
    }
}

#[cfg(test)]
mod tests;
