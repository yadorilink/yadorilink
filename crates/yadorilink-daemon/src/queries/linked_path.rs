//! Resolves an absolute filesystem path to its `(group_id, relative_path)`
//! pair -- a thin `Arc<SyncState>`-holding wrapper around `shell_status`'s
//! resolver, in the same shape as the other query services so callers go
//! through `context.queries.linked_path` rather than reaching for the free
//! function directly. Shared by `FileHistoryQueryService`'s read paths and
//! (later) the materialization/restore command services, which all resolve
//! the same absolute-path-to-group mapping before doing their own thing
//! with it.

use std::sync::Arc;

use crate::replica_coordinator::ReplicaCoordinator;

pub(crate) struct LinkedPathResolver {
    sync_state: Arc<ReplicaCoordinator>,
    /// The engine's state directory, where the Windows host records its sync roots.
    config_dir: std::path::PathBuf,
}

impl LinkedPathResolver {
    pub(crate) fn new(sync_state: Arc<ReplicaCoordinator>, config_dir: std::path::PathBuf) -> Self {
        Self { sync_state, config_dir }
    }

    pub(crate) fn resolve(&self, absolute_path: &str) -> Option<(String, String)> {
        crate::shell_status::resolve_group_and_rel_path(&self.sync_state, absolute_path)
    }

    /// The same for a path inside a File Provider location (a provider root has no directory).
    pub(crate) fn resolve_provider(&self, absolute_path: &str) -> Option<(String, String)> {
        crate::shell_status::resolve_provider_group_and_rel_path(
            &self.sync_state,
            &self.config_dir,
            absolute_path,
        )
    }
}
