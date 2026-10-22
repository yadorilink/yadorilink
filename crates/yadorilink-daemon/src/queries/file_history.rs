//! Version history and trash reads for `ListVersions`/`ListTrash` --
//! resolves an absolute path via `LinkedPathResolver`, then reads
//! `SyncState`'s already domain-shaped `VersionRecord`/`TrashedFile` rows
//! directly rather than inventing a parallel view type for them (they are
//! already plain, not protobuf).

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::{TrashedFile, VersionRecord};

use crate::queries::linked_path::LinkedPathResolver;
use crate::replica_coordinator::ReplicaCoordinator;

#[derive(Debug, Clone)]
pub(crate) struct TrashedFileView {
    pub(crate) local_path: String,
    pub(crate) trashed: TrashedFile,
}

/// A live (non-deleted) conflicted-copy file, tagged with its link's
/// `local_path` -- mirrors `TrashedFileView`'s own per-link tagging shape.
/// Same underlying set `LinkStatus.conflict_count` counts, by construction
/// (both read `list_live_conflict_copies`).
#[derive(Debug, Clone)]
pub(crate) struct ConflictedFileView {
    pub(crate) local_path: String,
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) mtime_unix_nanos: i64,
    pub(crate) record_kind: yadorilink_replica_domain::file::RecordKind,
    pub(crate) reason: ConflictCopyReason,
    /// Keep this / Keep both is offered: the same predicate the resolution
    /// itself checks.
    pub(crate) resolvable: bool,
    /// The device that authored the copy's current version, when known.
    pub(crate) origin_device_id: Option<String>,
}

pub(crate) use crate::conflict_resolution::ConflictCopyReason;

pub(crate) struct FileHistoryQueryService {
    sync_state: Arc<ReplicaCoordinator>,
    paths: Arc<LinkedPathResolver>,
}

impl FileHistoryQueryService {
    pub(crate) fn new(sync_state: Arc<ReplicaCoordinator>, paths: Arc<LinkedPathResolver>) -> Self {
        Self { sync_state, paths }
    }

    /// `None` when `absolute_path` isn't under any linked folder --
    /// distinct from `Ok(Some(vec![]))`, which means "resolved, no
    /// versions retained".
    pub(crate) fn list_versions(
        &self,
        absolute_path: &str,
    ) -> Result<Option<Vec<VersionRecord>>, SyncError> {
        let Some((group_id, path)) = self.paths.resolve(absolute_path) else {
            return Ok(None);
        };
        self.sync_state
            .sqlite()
            .dag_list_versions(&group_id, &path)
            .map(Some)
            .map_err(SyncError::from)
    }

    /// Every trashed file across every linked folder, each tagged with its
    /// link's own `local_path` -- mirrors `RuntimeStatusQueryService`'s own
    /// per-link iteration pattern.
    pub(crate) fn list_trash(&self) -> Result<Vec<TrashedFileView>, SyncError> {
        let mut out = Vec::new();
        for link in self.sync_state.link_repository().list_links()? {
            for trashed in self.sync_state.file_index_repository().list_trashed(&link.group_id)? {
                out.push(TrashedFileView { local_path: link.key().to_string(), trashed });
            }
        }
        Ok(out)
    }

    /// Every currently-live conflicted-copy file across every linked
    /// folder, each tagged with its link's own `local_path` -- same
    /// per-link iteration shape as `list_trash`. Reads
    /// `list_live_conflict_copies`, the same targeted query
    /// `LinkStatusReadPort::list_links`'s `conflict_count` reads from, so
    /// the two can never disagree about which paths count.
    pub(crate) fn list_conflicts(&self) -> Result<Vec<ConflictedFileView>, SyncError> {
        let mut out = Vec::new();
        for link in self.sync_state.link_repository().list_links()? {
            for file in
                self.sync_state.file_index_repository().list_live_conflict_copies(&link.group_id)?
            {
                let reason = crate::conflict_resolution::conflict_copy_reason(
                    &self.sync_state,
                    &link.group_id,
                    &file.path,
                )?;
                let resolvable = crate::conflict_resolution::conflict_copy_resolvable(
                    &file.path,
                    file.record_kind,
                    reason,
                );
                let origin_device_id = self
                    .sync_state
                    .sqlite()
                    .dag_list_versions(&link.group_id, &file.path)?
                    .into_iter()
                    .find(|version| {
                        version.state
                            == yadorilink_replica_domain::session_state::VersionState::Current
                    })
                    .and_then(|version| version.origin_device_id);
                out.push(ConflictedFileView {
                    local_path: link.key().to_string(),
                    path: file.path,
                    size: file.size,
                    mtime_unix_nanos: file.mtime_unix_nanos,
                    record_kind: file.record_kind,
                    reason,
                    resolvable,
                    origin_device_id,
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
