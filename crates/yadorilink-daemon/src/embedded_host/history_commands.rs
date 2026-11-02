//! Version history and deleted items of a provider folder, for the embedding app.
//!
//! Two read-only listings; the restore is not a call of its own. A restore is one ordinary new
//! write, so it is [`super::EngineCommands::apply_change`] with the request's `restore_from` set
//! to the `path` and `version_hash` a listing gave: MODIFY of a live item restores an earlier
//! version of it, CREATE brings a deleted file or folder back under the name and parent the
//! listing names. It has the operation identity, durability, conflict and role rules of every
//! other change, and a refusal changes nothing.
//!
//! What is listed is what the engine retains: the version history and the trash of
//! the history-retention design decide how long. A version whose bytes are no longer
//! held by any reachable device is still listed and is refused `VersionUnavailable` when
//! restored.

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::VersionState;
use yadorilink_sync_sqlite::provider::ItemId;

use super::{CommandError, EngineCommands};

/// How many deleted items one listing returns, newest first; `truncated` says there are more.
pub const MAX_DELETED_ITEMS: usize = 5_000;

/// What a version or a deleted entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryEntryKind {
    File,
    Directory,
    Symlink,
}

impl From<RecordKind> for HistoryEntryKind {
    fn from(kind: RecordKind) -> Self {
        match kind {
            RecordKind::File => Self::File,
            RecordKind::Directory => Self::Directory,
            RecordKind::Symlink => Self::Symlink,
        }
    }
}

/// Where a retained version stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryVersionState {
    /// The live version.
    Current,
    /// An earlier version a later edit replaced.
    Superseded,
    /// The last content before the item was deleted.
    Trashed,
}

/// One retained version of an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemVersion {
    /// Orders the versions of one path; the newest has the highest.
    pub version_seq: i64,
    /// The 32-byte identity a restore names.
    pub version_hash: Vec<u8>,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub state: HistoryVersionState,
    /// The device that authored it; `None` when unknown.
    pub origin_device_id: Option<String>,
    pub kind: HistoryEntryKind,
    /// A restore of it is offered: a file version other than the live one.
    pub restorable: bool,
}

/// The retained versions of one item, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemHistory {
    /// The group-relative path the versions are stored at: what a restore names.
    pub path: String,
    /// The item is live (not deleted).
    pub live: bool,
    pub versions: Vec<ItemVersion>,
}

/// Where a deleted item would come back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletedParent {
    /// The folder's root.
    Root,
    /// This live folder (its item id).
    Item(Vec<u8>),
    /// The folder it was in is deleted too: restore that folder first.
    Gone,
}

/// A deleted file or folder that can still be brought back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedItem {
    /// The group-relative path it had: what a restore names.
    pub path: String,
    /// The name to create it under.
    pub name: String,
    pub parent: DeletedParent,
    pub version_seq: i64,
    /// The 32-byte identity of its last content before the deletion: what a restore names.
    pub version_hash: Vec<u8>,
    pub size: u64,
    pub deleted_at_unix_nanos: i64,
    pub origin_device_id: Option<String>,
    pub kind: HistoryEntryKind,
    /// A restore is offered (a file or a folder; a symlink is not restorable).
    pub restorable: bool,
    /// Entries sharing it were removed by one recursive delete or folder rename.
    pub operation: Option<String>,
}

/// The deleted items of one provider folder, newest deletion first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedItems {
    pub items: Vec<DeletedItem>,
    /// More than [`MAX_DELETED_ITEMS`] exist; the oldest are not listed.
    pub truncated: bool,
}

fn group_of(
    coordinator: &crate::replica_coordinator::ReplicaCoordinator,
    root: &str,
) -> Result<String, CommandError> {
    coordinator
        .provider_repository()
        .group_of_root(root)
        .map_err(|e| CommandError::failed(e.to_string()))?
        .ok_or_else(|| CommandError::failed("unknown provider root"))
}

fn state_of(state: VersionState) -> HistoryVersionState {
    match state {
        VersionState::Current => HistoryVersionState::Current,
        VersionState::Superseded => HistoryVersionState::Superseded,
        VersionState::Trashed => HistoryVersionState::Trashed,
    }
}

impl EngineCommands {
    /// The retained versions of one item of a provider folder, newest first. Read-only. A retired
    /// (deleted) item still lists its history.
    ///
    /// # Errors
    /// [`CommandError`] when the root or the item is unknown, or the index cannot be read.
    pub fn list_item_versions(
        &self,
        root_id: &[u8],
        item_id: &[u8],
    ) -> Result<ItemHistory, CommandError> {
        let coordinator = &self.shell.replica_coordinator;
        let root = hex::encode(root_id);
        let group = group_of(coordinator, &root)?;
        let item = ItemId::try_from(item_id)
            .map_err(|_| CommandError::failed("an item id is not 16 bytes"))?;
        let (path, live) = coordinator
            .provider_repository()
            .path_for_item(&root, &item)
            .map_err(|e| CommandError::failed(e.to_string()))?
            .ok_or_else(|| CommandError::failed("unknown item"))?;
        let versions = coordinator
            .sqlite()
            .dag_list_versions(&group, &path)
            .map_err(|e| CommandError::failed(e.to_string()))?;
        Ok(ItemHistory {
            path,
            live,
            versions: versions
                .into_iter()
                .filter(|v| !v.deleted)
                .map(|v| ItemVersion {
                    version_seq: v.version_seq,
                    version_hash: v.version_hash.0.to_vec(),
                    size: v.size,
                    mtime_unix_nanos: v.mtime_unix_nanos,
                    state: state_of(v.state),
                    origin_device_id: v.origin_device_id,
                    kind: v.record_kind.into(),
                    restorable: v.state != VersionState::Current
                        && v.record_kind == RecordKind::File,
                })
                .collect(),
        })
    }

    /// The deleted files and folders of one provider folder that can still be brought back,
    /// newest deletion first. Read-only.
    ///
    /// # Errors
    /// [`CommandError`] when the root is unknown or the index cannot be read.
    pub fn list_deleted_items(&self, root_id: &[u8]) -> Result<DeletedItems, CommandError> {
        let coordinator = &self.shell.replica_coordinator;
        let repo = coordinator.provider_repository();
        let root = hex::encode(root_id);
        let group = group_of(coordinator, &root)?;
        let failed =
            |e: yadorilink_sync_sqlite::SyncSqliteError| CommandError::failed(e.to_string());
        let mut trashed =
            coordinator.file_index_repository().list_trashed(&group).map_err(failed)?;
        let truncated = trashed.len() > MAX_DELETED_ITEMS;
        trashed.truncate(MAX_DELETED_ITEMS);
        let mut items = Vec::with_capacity(trashed.len());
        for entry in trashed {
            let version_hash = coordinator
                .sqlite()
                .dag_list_versions(&group, &entry.path)
                .map_err(failed)?
                .into_iter()
                .find(|v| v.version_seq == entry.version_seq)
                .map(|v| v.version_hash.0.to_vec());
            // A trashed row whose version is gone cannot be named by a restore.
            let Some(version_hash) = version_hash else { continue };
            let (parent_path, name) = match entry.path.rsplit_once('/') {
                Some((parent, name)) => (parent, name),
                None => ("", entry.path.as_str()),
            };
            let parent = if parent_path.is_empty() {
                DeletedParent::Root
            } else if let Some(id) = repo.item_for_path(&root, parent_path).map_err(failed)? {
                DeletedParent::Item(id.to_vec())
            } else {
                // A live folder the OS never enumerated has no item yet: it gets one now.
                let live_folder = coordinator
                    .sqlite()
                    .dag_list_versions(&group, parent_path)
                    .map_err(failed)?
                    .into_iter()
                    .any(|v| {
                        v.state == VersionState::Current
                            && !v.deleted
                            && v.record_kind == RecordKind::Directory
                    });
                if live_folder {
                    DeletedParent::Item(
                        repo.mint_item(&root, parent_path).map_err(failed)?.to_vec(),
                    )
                } else {
                    DeletedParent::Gone
                }
            };
            items.push(DeletedItem {
                name: name.to_owned(),
                path: entry.path,
                parent,
                version_seq: entry.version_seq,
                version_hash,
                size: entry.last_known_size,
                deleted_at_unix_nanos: entry.deleted_at_unix_nanos,
                origin_device_id: entry.origin_device_id,
                kind: entry.record_kind.into(),
                restorable: entry.record_kind != RecordKind::Symlink,
                operation: entry.deleted_by_operation.map(|operation| {
                    format!("{}:{}", operation.author.as_str(), operation.operation_id.to_hex())
                }),
            });
        }
        Ok(DeletedItems { items, truncated })
    }
}
