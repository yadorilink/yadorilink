//! Version history and trash reads for `ListVersions`/`ListTrash` --
//! resolves an absolute path via `LinkedPathResolver`, then reads
//! `SyncState`'s already domain-shaped `VersionRecord`/`TrashedFile` rows
//! directly rather than inventing a parallel view type for them (they are
//! already plain, not protobuf).

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_local_storage::BlockStore;
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
    pub(crate) group_id: String,
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

/// What this device holds of each retained version. A version that is current, a deletion, a
/// directory or a symlink is not a statement about bytes; a file version is `Kept` when every
/// block it lists is present (an empty file lists none and is kept).
pub(crate) fn content_of_versions(
    store: &dyn BlockStore,
    records: Vec<VersionRecord>,
) -> Result<Vec<VersionView>, SyncError> {
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_replica_domain::session_state::VersionState;
    let has_bytes = |record: &VersionRecord| {
        record.state != VersionState::Current
            && !record.deleted
            && record.record_kind == RecordKind::File
    };
    let mut asked: Vec<String> = Vec::new();
    for record in records.iter().filter(|record| has_bytes(record)) {
        asked.extend(record.blocks.iter().map(|block| hex::encode(&block.hash)));
    }
    asked.sort();
    asked.dedup();
    let present: std::collections::HashSet<&String> = if asked.is_empty() {
        std::collections::HashSet::new()
    } else {
        let answers = store.present_blocks(&asked).map_err(SyncError::from)?;
        asked.iter().zip(answers).filter(|(_, held)| *held).map(|(hash, _)| hash).collect()
    };
    Ok(records
        .into_iter()
        .map(|record| {
            let content = if !has_bytes(&record) {
                VersionContent::NotApplicable
            } else if record.blocks.iter().all(|block| present.contains(&hex::encode(&block.hash)))
            {
                VersionContent::Kept
            } else {
                VersionContent::NotKept
            };
            VersionView { record, content }
        })
        .collect())
}

/// One recent-activity event, tagged with its link's `local_path`.
#[derive(Debug, Clone)]
pub(crate) struct ActivityView {
    /// For a conflict event, the device whose version holds the original path now (read at listing).
    pub(crate) other_origin_device_id: Option<String>,
    pub(crate) cursor: i64,
    pub(crate) local_path: String,
    pub(crate) event: yadorilink_sync_sqlite::activity::ActivityEvent,
    pub(crate) is_this_device: bool,
}

pub(crate) fn activity_query_from_proto(
    r: &yadorilink_ipc_proto::daemonctl::ListActivityRequest,
) -> yadorilink_sync_sqlite::activity::ActivityQuery {
    use yadorilink_ipc_proto::daemonctl::{ActivityKind as Wire, ActivityOrigin as WireOrigin};
    use yadorilink_sync_sqlite::activity::{ActivityKind, ActivityOrigin};
    yadorilink_sync_sqlite::activity::ActivityQuery {
        before_id: (r.before_cursor > 0).then_some(r.before_cursor),
        limit: r.limit,
        kinds: r
            .kinds()
            .filter_map(|kind| match kind {
                Wire::Unspecified => None,
                Wire::Added => Some(ActivityKind::Added),
                Wire::Updated => Some(ActivityKind::Updated),
                Wire::Deleted => Some(ActivityKind::Deleted),
                Wire::Conflict => Some(ActivityKind::Conflict),
                Wire::Restored => Some(ActivityKind::Restored),
            })
            .collect(),
        origin: match r.origin() {
            WireOrigin::Any => ActivityOrigin::Any,
            WireOrigin::ThisDevice => ActivityOrigin::ThisDevice,
            WireOrigin::OtherDevices => ActivityOrigin::OtherDevices,
        },
        group_ids: Vec::new(),
    }
}

pub(crate) fn activity_view_to_proto(
    view: ActivityView,
) -> yadorilink_ipc_proto::daemonctl::ActivityEventInfo {
    use yadorilink_ipc_proto::daemonctl::ActivityKind as Wire;
    use yadorilink_sync_sqlite::activity::ActivityKind;
    yadorilink_ipc_proto::daemonctl::ActivityEventInfo {
        cursor: view.cursor,
        local_path: view.local_path,
        path: view.event.path,
        kind: match view.event.kind {
            ActivityKind::Added => Wire::Added,
            ActivityKind::Updated => Wire::Updated,
            ActivityKind::Deleted => Wire::Deleted,
            ActivityKind::Conflict => Wire::Conflict,
            ActivityKind::Restored => Wire::Restored,
        } as i32,
        origin_device_id: view.event.origin_device_id.unwrap_or_default(),
        other_origin_device_id: view.other_origin_device_id.unwrap_or_default(),
        is_this_device: view.is_this_device,
        at_unix_nanos: view.event.at_unix_nanos,
    }
}

/// Whether this device holds the bytes of a retained version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VersionContent {
    /// Not a statement about bytes: the current version, a deletion, a directory.
    NotApplicable,
    /// Every block of the version is in the block store.
    Kept,
    /// At least one block is not in the block store: the version was replaced by this device's
    /// own edit or delete, or this device never held its content.
    NotKept,
}

/// A retained version and what this device holds of it.
#[derive(Debug, Clone)]
pub(crate) struct VersionView {
    pub(crate) record: VersionRecord,
    pub(crate) content: VersionContent,
}

pub(crate) struct FileHistoryQueryService {
    sync_state: Arc<ReplicaCoordinator>,
    paths: Arc<LinkedPathResolver>,
    /// This device, to tell its own activity from a peer's.
    device_id: String,
    /// Asked, in one batch per listing, which blocks of the older versions are held.
    block_store: Arc<dyn BlockStore + Send + Sync>,
}

impl FileHistoryQueryService {
    pub(crate) fn new(
        sync_state: Arc<ReplicaCoordinator>,
        paths: Arc<LinkedPathResolver>,
        device_id: String,
        block_store: Arc<dyn BlockStore + Send + Sync>,
    ) -> Self {
        Self { sync_state, paths, device_id, block_store }
    }

    /// The device that authored the current version of `path`, when the path has one and its author is
    /// known here. A read error says nothing rather than a wrong name.
    fn current_origin_device_id(&self, group_id: &str, path: &str) -> Option<String> {
        // A deleted path's current row is its tombstone: nobody holds the path. One row read.
        self.sync_state.file_index_repository().get_live_origin_device_id(group_id, path).ok()?
    }

    /// Recent activity across every linked folder, newest first.
    pub(crate) fn list_activity(
        &self,
        mut query: yadorilink_sync_sqlite::activity::ActivityQuery,
    ) -> Result<Vec<ActivityView>, SyncError> {
        let mut local_paths = std::collections::HashMap::new();
        for link in self.sync_state.link_repository().list_links()? {
            local_paths.insert(link.group_id.clone(), link.key().to_string());
        }
        query.group_ids = local_paths.keys().cloned().collect();
        let events =
            self.sync_state.file_index_repository().list_activity(&query, &self.device_id)?;
        Ok(events
            .into_iter()
            .filter_map(|event| {
                let local_path = local_paths.get(&event.group_id)?.clone();
                let is_this_device =
                    event.origin_device_id.as_deref().is_none_or(|origin| origin == self.device_id);
                // A conflict event's other side: whoever authored the version that holds the original path
                // now. A path that no longer exists, or whose author is not known, names nobody.
                // A copy of a copy carries more than one marker and its name no longer says which
                // path it was made from, so only a singly marked name is followed to its original.
                let other_origin_device_id = (event.kind
                    == yadorilink_sync_sqlite::activity::ActivityKind::Conflict
                    && event.path.matches("(conflicted copy").count() == 1)
                    .then(|| {
                        self.current_origin_device_id(
                            &event.group_id,
                            &yadorilink_replica_domain::conflict::conflict_copy_source_path(
                                &event.path,
                            ),
                        )
                    })
                    .flatten();
                Some(ActivityView {
                    cursor: event.id,
                    local_path,
                    event,
                    is_this_device,
                    other_origin_device_id,
                })
            })
            .collect())
    }

    /// `None` when `absolute_path` isn't under any linked folder --
    /// distinct from `Ok(Some(vec![]))`, which means "resolved, no
    /// versions retained".
    ///
    /// Each superseded or trashed version says whether its bytes are in the block store, from one
    /// batched presence check over the blocks of all of them (derived at the time of the listing,
    /// nothing is stored for it, and no block is read).
    pub(crate) fn list_versions(
        &self,
        absolute_path: &str,
    ) -> Result<Option<Vec<VersionView>>, SyncError> {
        let Some((group_id, path)) = self.paths.resolve_any(absolute_path) else {
            return Ok(None);
        };
        let records = self.sync_state.sqlite().dag_list_versions(&group_id, &path)?;
        content_of_versions(self.block_store.as_ref(), records).map(Some)
    }

    /// The unique bytes and the number of older versions the kept history holds that nothing
    /// current needs (what a limit on the history would act on).
    pub(crate) fn kept_history_usage(&self) -> Result<(u64, u64), SyncError> {
        // A block this device does not hold is no space used, whatever a kept row names.
        let store = self.block_store.clone();
        let held = move |hash: &[u8]| {
            store.present_blocks(&[hex::encode(hash)]).is_ok_and(|present| present == [true])
        };
        Ok(self.sync_state.file_index_repository().kept_history_usage(&held)?)
    }

    /// The events in which this device stopped keeping versions of the file at `absolute_path`
    /// (one entry per recorded event, oldest first), or `None` when the path is not under a link.
    pub(crate) fn not_kept_spans(
        &self,
        absolute_path: &str,
    ) -> Result<Option<Vec<yadorilink_sync_sqlite::history_freed::FreedSpan>>, SyncError> {
        let Some((group_id, path)) = self.paths.resolve_any(absolute_path) else {
            return Ok(None);
        };
        let mut spans =
            self.sync_state.database().read::<_, yadorilink_sync_sqlite::SyncSqliteError>(
                |conn| yadorilink_sync_sqlite::history_freed::spans_by_path(conn, &group_id),
            )?;
        Ok(Some(spans.remove(&path).unwrap_or_default()))
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
                ) && crate::conflict_resolution::resolvable_in_folder(
                    &self.sync_state,
                    &link.group_id,
                    &file.path,
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
                    group_id: link.group_id.clone(),
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
