//! A user's delete of the LOGICAL namespace, as opposed to an observation that
//! something this device had is gone.
//!
//! An observed removal (`FsChangeKind::ObservedRemoval`, from a watcher, a scan
//! or a journal replay) is evidence only where the row says an object was
//! here: a `Present` row's absence is a delete, a `Remote`, `Hydrating` or
//! `Evicting` row's absence is not. A [`SemanticDelete`] -- a platform
//! provider's `deleteItem` -- is the user acting on the namespace they saw, so
//! it is independent of any local object and applies to `Remote` rows too.
//!
//! What the user saw is what the delete covers. The set of live entries and
//! the version each had is captured when the delete is begun
//! ([`LocalChangeProcessor::begin_semantic_delete`]); an entry whose version
//! is not the one captured -- one a peer admitted, or replaced, after the
//! user's delete event -- was never seen by the user and is left alone.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::LocalCaptureError;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_sync_sqlite::CanonicalCurrentRow;

use super::event_ingest::EventOutcome;
use super::{LocalChangeOutcome, LocalChangeProcessor};

/// One user delete of `rel_path` (a file, or a directory and its logical
/// subtree), bound to the versions that were visible when it was begun.
#[derive(Debug, Clone)]
pub struct SemanticDelete {
    path: PathBuf,
    rel_path: String,
    /// Every live entry at `rel_path` or below it, with the version it had.
    visible: HashMap<String, VersionHash>,
}

impl SemanticDelete {
    /// Whether `row` (the live row at `path` now) is the version this delete
    /// saw there.
    pub(super) fn names_current_version(
        &self,
        path: &str,
        row: Option<&CanonicalCurrentRow>,
    ) -> bool {
        row.is_some_and(|row| self.visible.get(path) == Some(&row.version_hash()))
    }
}

/// Which kind of removal a subtree walk is carrying out.
#[derive(Clone, Copy)]
pub(super) enum Removal<'a> {
    Observed,
    Semantic(&'a SemanticDelete),
}

impl LocalChangeProcessor {
    /// Begins the user's delete of `rel_path` under `root`, capturing the
    /// versions visible now. Call it when the delete event arrives, before
    /// anything else can change what is visible.
    pub fn begin_semantic_delete(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: &str,
    ) -> Result<SemanticDelete, LocalCaptureError> {
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let prefix = format!("{rel_path}/");
        let mut visible = HashMap::new();
        for (row, _) in self.state.list_files_with_kind(group_id)? {
            if row.deleted || !(row.path == rel_path || row.path.starts_with(&prefix)) {
                continue;
            }
            match self.state.canonical_current_row(group_id, &row.path)? {
                Some(current) if !current.snapshot.deleted => {
                    visible.insert(row.path, current.version_hash());
                }
                _ => {}
            }
        }
        Ok(SemanticDelete { path: root.join(rel_path), rel_path: rel_path.to_owned(), visible })
    }

    /// [`Self::begin_semantic_delete`] for a root whose user saw the PUBLISHED versions, not the
    /// current ones (a provider root while an update is pending): each entry in `published` that
    /// is live is bound to the version the user was shown, so a newer version they never saw
    /// survives the delete instead of being erased.
    pub fn begin_semantic_delete_bound(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: &str,
        published: &HashMap<String, VersionHash>,
    ) -> Result<SemanticDelete, LocalCaptureError> {
        let mut delete = self.begin_semantic_delete(group_id, root, rel_path)?;
        for (path, version) in published {
            if let Some(visible) = delete.visible.get_mut(path) {
                *visible = *version;
            }
        }
        Ok(delete)
    }

    /// Carries out a [`SemanticDelete`]: the item, and for a directory every
    /// live entry below it that the delete saw, is tombstoned whatever its
    /// local state. An entry admitted or changed since the delete began is
    /// not deleted; a sibling that merely shares the name as a prefix is not
    /// under the directory.
    pub async fn process_semantic_delete(
        &self,
        group_id: &str,
        root: &Path,
        delete: &SemanticDelete,
    ) -> Result<LocalChangeOutcome, LocalCaptureError> {
        debug_assert!(!delete.rel_path.is_empty());
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        let event =
            FsChangeEvent { path: delete.path.clone(), kind: FsChangeKind::ObservedRemoval };
        match self
            .process_event_inner(group_id, root, &event, &ignore_set, None, None, Some(delete))
            .await?
        {
            EventOutcome::Ready(outcome) => Ok(outcome),
            EventOutcome::Deferred => unreachable!("no batch sink was given"),
        }
    }
}
