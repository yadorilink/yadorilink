//! The namespace steps of a reconcile pass: what a path has to be once
//! the tree around it is taken into account, and the disk work that gets
//! it there.
//!
//! Replication is per path; a filesystem is a tree. `a` cannot be a file
//! while `a/x` lives, and a directory this device made only to hold `a/x`
//! goes when `a/x` goes. The namespace projection
//! (`yadorilink_replica_engine::namespace`) decides the tree; these steps
//! carry it out for the paths a pass touches and their ancestors:
//!
//! * a path a live descendant needs becomes a directory (structural, or the
//!   explicit Directory its own heads name), and a File or Symlink there
//!   moves beside it under its conflict-copy name -- written there first,
//!   removed from the path only once the copy holds it;
//! * a directory this device created only for descendants is removed with
//!   a single non-recursive `rmdir` once nothing needs it and it is empty;
//! * a file whose name is held by a directory this device may not remove
//!   -- one holding content it does not replicate, or one it did not make
//!   -- stays at its copy name, and the path settles as retained instead of
//!   retrying.
//!
//! None of it is authored. The relocation removes the path's index row
//! rather than tombstoning it, so capture finds neither a file to delete
//! nor a directory it did not know about; every step bumps the path's
//! mutation fence before it touches disk.

use std::path::Path;

use yadorilink_peer_session::peer_session::PendingLocalFlushOutcome;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_sync_sqlite::desired_state::DesiredPathState;
use yadorilink_sync_sqlite::structural_origin::{
    StructuralOriginStatus, RETAINED_UNTRACKED_CONTENT,
};

use super::types::{MaterializeResult, SettlementEvidence};

fn sqlite_error(error: yadorilink_sync_sqlite::SyncSqliteError) -> PeerSessionError {
    PeerSessionError::from(crate::sync_error::SyncError::from(error))
}

/// Every proper ancestor of `path`, nearest first.
pub(crate) fn proper_ancestors(path: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(path.rsplit_once('/').map(|(parent, _)| parent), |p| {
        p.rsplit_once('/').map(|(parent, _)| parent)
    })
}

/// `path`'s parent, `""` for a path at the root.
pub(crate) fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// What [`LocalConvergenceExecutor::settle_directory_in_the_way`] decided.
pub(crate) enum DirectoryVerdict {
    Clear,
    Retry,
    Kept,
}

impl super::LocalConvergenceExecutor {
    /// What the namespace requires at `path` on its own account.
    pub(crate) fn desired_own_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<DesiredPathState, PeerSessionError> {
        self.state.desired_path_state(group_id, path).map_err(sqlite_error)
    }

    /// Makes `path` the directory its live descendants need, when it has no
    /// explicit entry of its own: keeps a directory already there, creates
    /// one (recorded as structural) when nothing is, and moves a File or
    /// Symlink out of the way (see [`Self::displace_leaf_for_directory`]).
    pub(crate) async fn settle_structural_container(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<MaterializeResult, PeerSessionError> {
        if !self.displace_leaf_for_directory(group_id, path).await? {
            return Ok(MaterializeResult::RetryRequired);
        }
        let path_lock = self.state.path_lock(group_id, path);
        let _guard = crate::receive_diag::lock_path(&path_lock).await;
        let out_path = self.local_file_path(group_id, path)?;
        match std::fs::symlink_metadata(&out_path) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Ok(MaterializeResult::RetryRequired),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.create_structural_directory_at(group_id, &out_path)?;
            }
            Err(e) => return Err(PeerSessionError::from(e)),
        }
        let identity = yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path)
            .ok()
            .filter(|identity| {
                identity.object_kind == yadorilink_fs_platform::fs_identity::ObjectKind::Directory
            });
        let Some(identity) = identity else {
            return Ok(MaterializeResult::RetryRequired);
        };
        self.retire_superseded_directory_entry(group_id, path, &out_path, &identity)?;
        let mutation_generation = self.state.directory_settlement_generation(group_id, path)?;
        Ok(MaterializeResult::Settled(SettlementEvidence::StructuralDirectory {
            identity: Box::new(Some(identity)),
            mutation_generation,
        }))
    }

    /// The explicit Directory entry a directory kept only for descendants
    /// used to be: its index row still claims the path, which a structural
    /// directory's proof can never be published over. The row is removed
    /// -- the entry is superseded, not deleted by this device -- and the
    /// directory, when it is the very object this device materialized for
    /// that entry, is adopted as structural, so it goes with the last
    /// descendant. A directory the user put there instead stays theirs.
    ///
    /// The caller holds `path`'s lock.
    fn retire_superseded_directory_entry(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
    ) -> Result<(), PeerSessionError> {
        let live_directory_row =
            self.state.get_file(group_id, path)?.is_some_and(|row| !row.deleted)
                && self.state.get_record_kind(group_id, path)? == Some(RecordKind::Directory);
        if !live_directory_row {
            return Ok(());
        }
        if self.is_materialized_directory_at(group_id, path, out_path)? {
            self.state
                .adopt_as_structural_directory(group_id, path, identity)
                .map_err(sqlite_error)?;
        }
        let authority = self.root_lease_for(group_id)?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        let (intent, _mutation_generation) =
            self.state.open_tombstone_delete(group_id, path, &permit)?;
        self.state.settle_retired_copy_erase(intent, group_id, path, &permit)?;
        tracing::debug!(
            group_id,
            path,
            "a superseded directory entry stays on disk only for its live descendants"
        );
        Ok(())
    }

    /// Clears a File or Symlink out of `path`, which has to become a
    /// directory. `true` when nothing but a directory (or nothing at all)
    /// is left there.
    ///
    /// The leaf goes only when disk still holds exactly what its index row
    /// says (an edit nobody captured is captured first, and the path
    /// retried), and under the path lock with the fence bumped and a delete
    /// intent open. The caller has already checked the displacement guard:
    /// the content, if it lives on elsewhere, is on disk there. Its index row
    /// is removed, not tombstoned: the entry is not deleted, and a row that
    /// claimed it at `path` would read to capture as a file gone missing.
    pub(crate) async fn displace_leaf_for_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        let leaf_on_disk = std::fs::symlink_metadata(&out_path).is_ok_and(|meta| !meta.is_dir());
        let row_claims_leaf = self.state.get_file(group_id, path)?.is_some_and(|row| !row.deleted)
            && self.state.get_record_kind(group_id, path)? != Some(RecordKind::Directory);
        if !leaf_on_disk && !row_claims_leaf {
            return Ok(true);
        }
        if leaf_on_disk && !row_claims_leaf {
            // Nothing this device replicates is there: content it has not
            // captured, which it never removes.
            return Ok(false);
        }
        if self.flush_local_changes_before_reconcile(group_id, path).await
            == PendingLocalFlushOutcome::RetryRequired
        {
            return Ok(false);
        }
        let path_lock = self.state.path_lock(group_id, path);
        let _guard = crate::receive_diag::lock_path(&path_lock).await;
        // Looked at again under the lock: what stood here before the flush
        // and lock awaits may have been replaced since.
        if std::fs::symlink_metadata(&out_path).is_ok_and(|meta| !meta.is_dir()) {
            if self.removal_would_destroy_unrecorded_state(group_id, path, &out_path)? {
                tracing::info!(
                    group_id,
                    path,
                    "not moving a file out of a name its live descendants need: it holds an \
                     edit this device has not captured yet"
                );
                return Ok(false);
            }
            self.verify_delete_target(group_id, &out_path)?;
        }
        // Under the lock, with the content that is there now: what this path
        // gives up lives on elsewhere and is on disk there (and the platform can
        // make that durable), or the path waits.
        if !self.displacement_allowed(group_id, path, None).await? {
            return Ok(false);
        }
        let authority = self.root_lease_for(group_id)?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        let (intent, _mutation_generation) =
            self.state.open_tombstone_delete(group_id, path, &permit)?;
        if !std::fs::symlink_metadata(&out_path).is_ok_and(|meta| meta.is_dir()) {
            // Durable before the row is erased; a leaf already gone only needs
            // its absence made durable.
            yadorilink_local_storage::remove_durably(&out_path, &self.state.temp_ledger(group_id))?;
        }
        #[cfg(test)]
        super::removal_ordering_probe::fire(&out_path);
        self.state.settle_retired_copy_erase(intent, group_id, path, &permit)?;
        tracing::debug!(group_id, path, "moved a file out of a name its live descendants need");
        Ok(true)
    }

    /// What to do about a directory standing at the name an entry needs:
    /// remove it when this device made it only for descendants that are gone
    /// (or it is the superseded replicated directory, and empty), wait while
    /// replicated entries below still await their deletes, or keep it for
    /// good, in which case the entry has to live at another name.
    pub(crate) async fn settle_directory_in_the_way(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<DirectoryVerdict, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        if !std::fs::symlink_metadata(&out_path).is_ok_and(|meta| meta.is_dir()) {
            return Ok(DirectoryVerdict::Clear);
        }
        let reason = {
            let path_lock = self.state.path_lock(group_id, path);
            let _guard = crate::receive_diag::lock_path(&path_lock).await;
            if self.prune_directory_made_for_descendants(group_id, path)?.is_some() {
                return Ok(DirectoryVerdict::Clear);
            }
            // The replicated directory the new entry supersedes: removed
            // like a Directory tombstone's target, when it is empty.
            // Only the very object this device materialized for it: a
            // directory the user put there in its place is theirs.
            let replicated_directory =
                self.state.get_file(group_id, path)?.is_some_and(|row| !row.deleted)
                    && self.state.get_record_kind(group_id, path)? == Some(RecordKind::Directory)
                    && self.is_materialized_directory_at(group_id, path, &out_path)?;
            if replicated_directory && self.remove_superseded_directory(group_id, path)? {
                return Ok(DirectoryVerdict::Clear);
            }
            if self.holds_tracked_content(group_id, path, &out_path)? {
                // Replicated entries below still wait for their deletes,
                // in a pass of their own: not content this device keeps,
                // and the pass that removes the last of them brings this
                // path back.
                return Ok(DirectoryVerdict::Retry);
            }
            let observed =
                yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path).ok();
            let structural = self.origin_status(group_id, path, observed.as_ref())?
                == StructuralOriginStatus::Structural;
            let reason = RETAINED_UNTRACKED_CONTENT;
            // This device made it, adopted it, or held it as a replicated
            // directory: once it is empty, it may go. Anything else is kept
            // for good.
            let removable = if structural || replicated_directory { observed } else { None };
            self.state
                .keep_retained_directory(group_id, path, reason, removable.as_ref())
                .map_err(sqlite_error)?;
            reason
        };
        tracing::info!(
            group_id,
            path,
            "a directory this device may not remove holds the name an entry needs; the entry \
             waits"
        );
        let _ = reason;
        Ok(DirectoryVerdict::Kept)
    }

    /// Whether anything under the directory at `path` (`out_path`) is an
    /// entry this device's index tracks as live. Only directories this
    /// device made for descendants are searched below: a tracked entry sits
    /// under tracked or structural directories all the way down.
    fn holds_tracked_content(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
    ) -> Result<bool, PeerSessionError> {
        let mut pending = vec![(path.to_string(), out_path.to_path_buf())];
        while let Some((rel, dir)) = pending.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                let child = format!("{rel}/{name}");
                if self.state.get_file(group_id, &child)?.is_some_and(|row| !row.deleted) {
                    return Ok(true);
                }
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let observed =
                    yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&entry.path())
                        .ok();
                if self.origin_status(group_id, &child, observed.as_ref())?
                    == StructuralOriginStatus::Structural
                {
                    pending.push((child, entry.path()));
                }
            }
        }
        Ok(false)
    }

    /// Removes the directory at `path` if this device created (or adopted)
    /// exactly that object only to hold descendants, the namespace needs
    /// nothing there any more, and it is empty: one non-recursive `rmdir`,
    /// after a fence bump. `ExactAbsent` when it went; `None` when it stays
    /// (not structural, still needed, not empty, or not a directory).
    ///
    /// The caller holds `path`'s lock. The identity check and the `rmdir`
    /// are two steps, and the `rmdir` goes by name: the same window
    /// `LocalConvergenceExecutor::remove_directory_if_empty` documents, where
    /// only an empty directory swapped in at this name between the two, by
    /// a process that does not take this daemon's path lock, can be removed
    /// in its place. That helper is not reused here because it records a
    /// directory it finds not empty as retained, bound to its identity for
    /// a later removal; a structural directory that still holds something
    /// is simply left as it is.
    pub(crate) fn prune_directory_made_for_descendants(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        use yadorilink_local_storage::EmptyDirectoryRemoval;
        let out_path = self.local_file_path(group_id, path)?;
        let Ok(observed) =
            yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path)
        else {
            self.forget_structural_record_of_a_removed_directory(group_id, path, &out_path)?;
            return Ok(None);
        };
        if self.origin_status(group_id, path, Some(&observed))?
            != StructuralOriginStatus::Structural
        {
            return Ok(None);
        }
        if matches!(
            self.desired_own_state(group_id, path)?,
            DesiredPathState::StructuralDirectory | DesiredPathState::ExplicitDirectory { .. }
        ) {
            return Ok(None);
        }
        self.verify_delete_target(group_id, &out_path)?;
        let mutation_generation =
            self.state.begin_directory_removal(group_id, path, "structural_directory_rmdir")?;
        Ok(
            match yadorilink_local_storage::remove_empty_dir_in(
                &out_path,
                &self.state.temp_ledger(group_id),
            )? {
                EmptyDirectoryRemoval::Removed | EmptyDirectoryRemoval::Absent => {
                    self.state.forget_removed_directory(group_id, path).map_err(sqlite_error)?;
                    tracing::debug!(
                    group_id,
                    path,
                    "removed a directory this device created only for descendants that are gone"
                );
                    Some(SettlementEvidence::ExactAbsent { mutation_generation })
                }
                EmptyDirectoryRemoval::NotEmpty
                | EmptyDirectoryRemoval::NotADirectory
                | EmptyDirectoryRemoval::Stranded(_) => None,
            },
        )
    }

    /// Nothing is at `path` (`out_path`), yet a structural directory is
    /// recorded there: one this device removed, stopped (a crash, an error)
    /// before it forgot the record. The record names nothing any more and
    /// nothing else would ever look at it, so it is forgotten now. A pending
    /// `mkdir` intent is not a record of a removed directory, and stays.
    ///
    /// The caller holds `path`'s lock.
    fn forget_structural_record_of_a_removed_directory(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
    ) -> Result<(), PeerSessionError> {
        use yadorilink_sync_sqlite::structural_origin::StructuralDirectoryOrigin;
        if !matches!(
            std::fs::symlink_metadata(out_path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        ) {
            return Ok(());
        }
        let recorded = self
            .state
            .sqlite()
            .dag_structural_directory_origin(group_id, path)
            .map_err(sqlite_error)?;
        if matches!(recorded, StructuralDirectoryOrigin::Recorded(_)) {
            self.state.forget_removed_directory(group_id, path).map_err(sqlite_error)?;
        }
        Ok(())
    }

    /// One non-recursive `rmdir` of the replicated directory at `path`,
    /// after a fence bump, for an entry that supersedes it. `true` when it
    /// is gone. The caller holds `path`'s lock. Between the identity check
    /// and the `rmdir` by name lies the window `remove_directory_if_empty`
    /// documents; only an empty directory can be affected.
    fn remove_superseded_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_local_storage::EmptyDirectoryRemoval;
        let out_path = self.local_file_path(group_id, path)?;
        self.verify_delete_target(group_id, &out_path)?;
        self.state.begin_directory_removal(group_id, path, "superseded_directory_rmdir")?;
        Ok(
            match yadorilink_local_storage::remove_empty_dir_in(
                &out_path,
                &self.state.temp_ledger(group_id),
            )? {
                EmptyDirectoryRemoval::Removed | EmptyDirectoryRemoval::Absent => {
                    self.state.forget_removed_directory(group_id, path).map_err(sqlite_error)?;
                    true
                }
                EmptyDirectoryRemoval::NotEmpty
                | EmptyDirectoryRemoval::NotADirectory
                | EmptyDirectoryRemoval::Stranded(_) => false,
            },
        )
    }

    fn origin_status(
        &self,
        group_id: &str,
        path: &str,
        observed: Option<&yadorilink_fs_platform::fs_identity::FileIdentity>,
    ) -> Result<StructuralOriginStatus, PeerSessionError> {
        self.state
            .structural_origin_status(group_id, path, &self.sync_root(group_id)?, observed)
            .map_err(sqlite_error)
    }

    /// Creates the directory at `out_path` itself (and any missing
    /// ancestor) through the recording `mkdir` helper, so each one is
    /// bound to its identity as structural.
    fn create_structural_directory_at(
        &self,
        group_id: &str,
        out_path: &Path,
    ) -> Result<(), PeerSessionError> {
        let raw_root = self.sync_root(group_id)?;
        self.state.verify_root(&raw_root, group_id)?;
        let canonical_root = self.canonical_sync_root(group_id, &raw_root).ok_or_else(|| {
            PeerSessionError::PathEscapesRoot(format!(
                "the root of group {group_id} cannot be resolved; not creating {}",
                out_path.display()
            ))
        })?;
        Ok(yadorilink_local_storage::create_dir_all_never_through_a_symlink(
            out_path,
            &canonical_root,
            out_path,
            &self.structural_ledger(group_id),
        )?)
    }

    /// Whether a directory (not a symlink to one) stands at `path` on disk.
    pub(crate) fn directory_on_disk(&self, group_id: &str, path: &str) -> bool {
        self.local_file_path(group_id, path)
            .is_ok_and(|out| std::fs::symlink_metadata(out).is_ok_and(|meta| meta.is_dir()))
    }

    /// Whether a directory holds `path`'s name on this volume under another
    /// exact spelling (`a/` for `A`): the entry cannot take its name here.
    pub(crate) fn folded_directory_holds_name(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        if !std::fs::symlink_metadata(&out_path).is_ok_and(|meta| meta.is_dir()) {
            return Ok(false);
        }
        Ok(self.exact_name_folded_elsewhere(&out_path)?.is_some())
    }

    /// Whether an entry of the parent directory is `path`'s last component as this volume
    /// lists it: the same bytes, or (on a volume that stores names decomposed) the same name
    /// up to Unicode normalisation. Case is never folded: a lookup of the name proves nothing
    /// of the kind, which is why the directory is listed.
    pub(crate) fn exact_leaf_listed(
        &self,
        group_id: &str,
        path: &str,
        volume: super::types::VolumeFolding,
    ) -> Result<bool, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        let (Some(parent), Some(name)) = (out_path.parent(), out_path.file_name()) else {
            return Ok(false);
        };
        let Ok(entries) = std::fs::read_dir(parent) else { return Ok(false) };
        Ok(entries.flatten().any(|entry| {
            listed_name_is(&entry.file_name(), name, volume.normalization_insensitive)
        }))
    }

    /// When `out_path` answers a lookup but no entry of its parent has its
    /// exact name, the name of the entry that answered (the one the volume
    /// folds it to). `None` when the exact name exists, or nothing answers.
    fn exact_name_folded_elsewhere(
        &self,
        out_path: &Path,
    ) -> Result<Option<String>, PeerSessionError> {
        let (Some(parent), Some(name)) = (out_path.parent(), out_path.file_name()) else {
            return Ok(None);
        };
        Ok(entry_answering_under_another_name(parent, name, out_path)?)
    }
}

/// Whether a listed entry name is `name`: byte-equal, or, when the volume does not tell
/// normalisation forms apart, equal after NFC (case still exact).
pub(super) fn listed_name_is(
    listed: &std::ffi::OsStr,
    name: &std::ffi::OsStr,
    normalization_insensitive: bool,
) -> bool {
    if listed == name {
        return true;
    }
    if !normalization_insensitive {
        return false;
    }
    match (listed.to_str(), name.to_str()) {
        (Some(listed), Some(name)) => {
            yadorilink_fs_platform::canonical_fold::nfc(listed)
                == yadorilink_fs_platform::canonical_fold::nfc(name)
        }
        _ => false,
    }
}

/// The name of the entry of `parent` that is the object `target` (the path
/// `parent/name` answered) names, when no entry of `parent` is spelled
/// exactly `name`. `None` when `name` itself exists, or no entry
/// is that object.
fn entry_answering_under_another_name(
    parent: &Path,
    name: &std::ffi::OsStr,
    target: &Path,
) -> std::io::Result<Option<String>> {
    let mut answered = None;
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        if entry.file_name() == name {
            return Ok(None);
        }
        // Object identity (not size and times, which two siblings can share); neither path is
        // followed if it is a symlink: a symlink, dangling or not, compares as the link itself.
        if yadorilink_fs_platform::fs_identity::same_live_object(&entry.path(), target) {
            answered = entry.file_name().to_str().map(str::to_string);
        }
    }
    Ok(answered)
}

#[cfg(test)]
mod tests {
    use super::entry_answering_under_another_name;

    /// What a folding volume's lookup of `name` returns, on any volume:
    /// the entry `A` itself, not what it points to.
    fn lookup_answer(dir: &std::path::Path, spelled: &str) -> std::path::PathBuf {
        dir.join(spelled)
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_answering_under_another_spelling_is_found() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t"), b"target").unwrap();
        std::os::unix::fs::symlink("t", dir.path().join("A")).unwrap();

        let target = lookup_answer(dir.path(), "A");
        let found = entry_answering_under_another_name(dir.path(), "a".as_ref(), &target).unwrap();

        assert_eq!(found.as_deref(), Some("A"));
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_answering_under_another_spelling_is_found() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("nowhere", dir.path().join("A")).unwrap();

        let target = lookup_answer(dir.path(), "A");
        let found = entry_answering_under_another_name(dir.path(), "a".as_ref(), &target).unwrap();

        assert_eq!(found.as_deref(), Some("A"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_the_looked_up_object_is_not_the_entry_that_answered() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("A"), b"file").unwrap();
        std::os::unix::fs::symlink("A", dir.path().join("link")).unwrap();

        let target = lookup_answer(dir.path(), "A");
        let found = entry_answering_under_another_name(dir.path(), "a".as_ref(), &target).unwrap();

        assert_eq!(found.as_deref(), Some("A"), "the link to it must not answer");
    }

    #[test]
    fn the_exact_name_existing_answers_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"file").unwrap();

        let target = lookup_answer(dir.path(), "a");
        let found = entry_answering_under_another_name(dir.path(), "a".as_ref(), &target).unwrap();

        assert_eq!(found, None);
    }

    /// Two siblings written together share size and times; only the entry that is the object
    /// itself answers.
    #[test]
    fn a_sibling_with_the_same_size_and_times_is_not_the_entry_that_answered() {
        let dir = tempfile::tempdir().unwrap();
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        for name in ["A", "B"] {
            let file = std::fs::File::create(dir.path().join(name)).unwrap();
            std::io::Write::write_all(&mut &file, b"same").unwrap();
            file.set_modified(when).unwrap();
        }

        let target = lookup_answer(dir.path(), "A");
        let found = entry_answering_under_another_name(dir.path(), "a".as_ref(), &target).unwrap();

        assert_eq!(found.as_deref(), Some("A"));
    }
}

#[cfg(test)]
mod listed_name_tests {
    use super::listed_name_is;
    use std::ffi::OsStr;

    const COMPOSED: &str = "caf\u{e9}.jpg";
    const DECOMPOSED: &str = "cafe\u{301}.jpg";

    #[test]
    fn a_decomposed_listing_is_the_composed_name_on_a_normalisation_blind_volume_only() {
        assert!(listed_name_is(OsStr::new(DECOMPOSED), OsStr::new(COMPOSED), true));
        assert!(!listed_name_is(OsStr::new(DECOMPOSED), OsStr::new(COMPOSED), false));
    }

    #[test]
    fn case_is_never_folded() {
        assert!(!listed_name_is(OsStr::new("Photo.jpg"), OsStr::new("photo.jpg"), true));
        assert!(!listed_name_is(OsStr::new("Caf\u{e9}.jpg"), OsStr::new(COMPOSED), true));
        assert!(listed_name_is(OsStr::new("photo.jpg"), OsStr::new("photo.jpg"), false));
    }
}
