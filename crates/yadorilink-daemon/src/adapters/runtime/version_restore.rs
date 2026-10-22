//! `hydration`-backed [`VersionRestorePort`].

use std::sync::Arc;

use crate::sync_error::SyncError;

use crate::application::ports::{BoxFuture, VersionRestorePort};
use crate::daemon_state::DaemonState;
use crate::hydration;

pub(crate) struct DaemonVersionRestoreAdapter {
    state: Arc<DaemonState>,
}

impl DaemonVersionRestoreAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl VersionRestorePort for DaemonVersionRestoreAdapter {
    fn most_recent_superseded_version_seq(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<i64>, SyncError> {
        hydration::most_recent_superseded_version_seq(&self.state, group_id, path)
    }

    fn restore_to_version<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        version_seq: i64,
    ) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(hydration::restore_to_version(&self.state, group_id, path, version_seq))
    }

    fn restore_trashed<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(hydration::restore_trashed(&self.state, group_id, path))
    }

    fn restore_trashed_operation<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<hydration::TrashOperationRestore, SyncError>> {
        Box::pin(hydration::restore_trashed_operation(&self.state, group_id, path))
    }

    fn resolve_conflict<'a>(
        &'a self,
        group_id: &'a str,
        copy_path: &'a str,
        choice: crate::application::ports::version_restore::ConflictChoice,
    ) -> BoxFuture<
        'a,
        Result<
            std::path::PathBuf,
            crate::application::ports::version_restore::ResolveConflictError,
        >,
    > {
        Box::pin(crate::conflict_resolution::resolve_conflict(
            &self.state,
            group_id,
            copy_path,
            choice,
        ))
    }
}
