//! Sync problems of a provider folder, for the embedding app: conflict copies and how to settle
//! them, the publications waiting on the operating system, and retrying a preserved item.
//!
//! Each call runs the service the daemon's control socket runs for the same request. A conflict
//! copy is named the way the provider surface names an item (`root_id`, `item_id`); the choice
//! is the daemon's own (`Keep this`, `Keep both`) and every precondition is read again by the
//! service while it runs.

use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode;
use yadorilink_sync_sqlite::provider::ProviderDeclaration;

use super::{CommandError, EngineCommands, PreservedRef};
use crate::application::ports::version_restore::{ConflictChoice, ResolveConflictError};

/// Why a conflict copy exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictReason {
    /// Concurrent changes to the same path; the copy holds the version that did not win.
    ConcurrentEdit,
    /// The original name is a folder now, so the file was moved aside.
    FolderAtPath,
}

/// One conflict copy of a provider folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictedFile {
    pub root_id: Vec<u8>,
    /// The copy's item: what `resolve_conflict` names.
    pub item_id: Vec<u8>,
    /// The group-relative path of the copy.
    pub path: String,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub reason: ConflictReason,
    /// Keep this / Keep both is offered: the predicate the resolution itself checks.
    pub resolvable: bool,
    /// The device that authored the copy's current version, when known.
    pub origin_device_id: Option<String>,
}

/// How to settle a conflict copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// The copy's content becomes the file under the original name (the replaced version stays in
    /// its history); the copy stays as it is.
    KeepThis,
    /// The copy is kept beside the original under a free `name (other version N)` name.
    KeepBoth,
}

/// A change waiting on the operating system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPublication {
    /// The first characters of the root's id.
    pub root_id: String,
    pub path: String,
    pub age_ms: u64,
}

impl EngineCommands {
    /// Every live conflict copy of a provider folder.
    ///
    /// # Errors
    /// [`CommandError`] when the index cannot be read.
    pub fn list_conflicts(&self) -> Result<Vec<ConflictedFile>, CommandError> {
        let views = self
            .context
            .queries
            .file_history
            .list_conflicts()
            .map_err(|e| CommandError::from_error(&e))?;
        let repo = self.shell.replica_coordinator.provider_repository();
        let mut out = Vec::new();
        for view in views {
            let ProviderDeclaration::Provider(root) = repo
                .declaration_for_group(&view.group_id)
                .map_err(|e| CommandError::from_error(&e))?
            else {
                continue;
            };
            let Some(item) = repo
                .item_for_path(&root.root_id, &view.path)
                .map_err(|e| CommandError::from_error(&e))?
            else {
                continue;
            };
            let Ok(root_id) = hex::decode(&root.root_id) else { continue };
            out.push(ConflictedFile {
                root_id,
                item_id: item.to_vec(),
                path: view.path,
                size: view.size,
                mtime_unix_nanos: view.mtime_unix_nanos,
                reason: match view.reason {
                    crate::queries::file_history::ConflictCopyReason::ConcurrentEdit => {
                        ConflictReason::ConcurrentEdit
                    }
                    crate::queries::file_history::ConflictCopyReason::FolderAtPath => {
                        ConflictReason::FolderAtPath
                    }
                },
                resolvable: view.resolvable,
                origin_device_id: view.origin_device_id,
            });
        }
        Ok(out)
    }

    /// Settles one conflict copy and returns the path that holds its content afterwards.
    ///
    /// # Errors
    /// `Refused(TargetNotFound)` for a copy that is gone or is not a conflict copy,
    /// `Refused(ConflictNotResolvable)` and `Refused(UnrecordedLocalChanges)` as the daemon
    /// answers them; [`CommandError`] otherwise.
    pub async fn resolve_conflict(
        &self,
        root_id: &[u8],
        item_id: &[u8],
        resolution: ConflictResolution,
    ) -> Result<String, CommandError> {
        let (group, path) = self.resolve_item(root_id, item_id)?;
        let choice = match resolution {
            ConflictResolution::KeepThis => ConflictChoice::KeepThis,
            ConflictResolution::KeepBoth => ConflictChoice::KeepBoth,
        };
        match self.context.application.version_restore.resolve_conflict(&group, &path, choice).await
        {
            Ok(kept) => Ok(kept.to_string_lossy().into_owned()),
            Err(error) => {
                let code = match &error {
                    ResolveConflictError::NotAConflictCopy(_) => {
                        ApplicationErrorCode::TargetNotFound
                    }
                    ResolveConflictError::NotResolvable(_) => {
                        ApplicationErrorCode::ConflictNotResolvable
                    }
                    ResolveConflictError::UnrecordedLocalChanges(_) => {
                        ApplicationErrorCode::UnrecordedLocalChanges
                    }
                    ResolveConflictError::Failed(sync) => {
                        return Err(CommandError::from_error(sync));
                    }
                };
                Err(CommandError::refused(code, error.to_string(), String::new()))
            }
        }
    }

    /// Up to `limit` publications waiting on the operating system per folder, oldest first. A
    /// read that fails is an error, never an empty list.
    ///
    /// # Errors
    /// [`CommandError`] when the read fails.
    pub fn list_provider_pending(
        &self,
        limit: u32,
    ) -> Result<Vec<PendingPublication>, CommandError> {
        self.context
            .provider_status
            .pending_items(limit)
            .map(|items| {
                items
                    .into_iter()
                    .map(|p| PendingPublication {
                        root_id: p.root_id,
                        path: p.path,
                        age_ms: p.age_ms,
                    })
                    .collect()
            })
            .map_err(CommandError::failed)
    }

    /// Asks the engine to try a preserved item again.
    ///
    /// # Errors
    /// [`super::CommandErrorKind::Preserved`] for the item's own refusals.
    pub async fn retry_preserved(&self, item: PreservedRef) -> Result<(), CommandError> {
        self.context
            .application
            .preserved
            .retry(item.group_id, item.item_id)
            .await
            .map_err(super::app_commands::preserved_failure)
    }
}
