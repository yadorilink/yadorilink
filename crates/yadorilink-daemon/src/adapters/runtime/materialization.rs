//! `hydration`-backed [`MaterializationPort`].

use std::sync::Arc;

use crate::sync_error::SyncError;

use crate::application::ports::{
    BoxFuture, EvictOutcome, MaterializationPort, MaterializationStatusSummary, PinOutcome,
    RetentionState,
};
use crate::daemon_state::DaemonState;
use crate::hydration;
use crate::hydration::directory;
use yadorilink_replica_domain::session_state::MaterializationState;

pub(crate) struct DaemonMaterializationAdapter {
    state: Arc<DaemonState>,
}

impl DaemonMaterializationAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

/// A folder is asked for as a whole: every request acts on the files below
/// it (see `hydration::directory`). Anything else is one file.
/// The paths in the order their locks are taken, each lock once: a lock is keyed by the path's
/// case/normalization fold, so names that fold together are one lock, and holders that order by
/// the same key can never wait on each other in a cycle.
fn lock_order(paths: Vec<String>) -> Vec<String> {
    let mut by_lock_key = std::collections::BTreeMap::new();
    for path in paths {
        by_lock_key
            .entry(yadorilink_fs_platform::canonical_fold::canonical_fold(&path))
            .or_insert(path);
    }
    by_lock_key.into_values().collect()
}

impl DaemonMaterializationAdapter {
    /// Fetches what a pin keeps. A folder visits every file beneath it, not only the ones
    /// that look absent: each visit reads the file's state under its own lock, which is what
    /// brings back a file an eviction that began before the pin finished freeing.
    async fn fetch_kept(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        if directory::is_indexed_directory(&self.state, group_id, path)? {
            directory::hydrate_every_file(&self.state, group_id, path).await?;
            self.state.nudge_custody_hold_reconciler();
            Ok(())
        } else {
            self.hydrate(group_id, path).await
        }
    }
}

impl MaterializationPort for DaemonMaterializationAdapter {
    fn materialize_to_temp<'a>(
        &'a self,
        request: crate::application::ports::TempMaterialization<'a>,
    ) -> BoxFuture<'a, Result<crate::application::ports::TempOutcome, SyncError>> {
        Box::pin(async move {
            match hydration::materialize_path(
                &self.state,
                request.group_id,
                request.path,
                hydration::Sink::Temp(&request),
            )
            .await?
            {
                hydration::Materialized::Temp(outcome) => Ok(outcome),
                hydration::Materialized::InPlace => Err(SyncError::CorruptState(
                    "a temp materialization produced an in-place result".into(),
                )),
            }
        })
    }

    fn hydrate<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(async move {
            let path = path.trim_end_matches('/');
            let result = if directory::is_indexed_directory(&self.state, group_id, path)? {
                directory::hydrate_directory(&self.state, group_id, path).await
            } else {
                hydration::materialize_path(&self.state, group_id, path, hydration::Sink::InPlace)
                    .await
                    .map(|_| ())
            };
            // A rehydrated path no longer depends on a custody lease.
            self.state.nudge_custody_hold_reconciler();
            result
        })
    }

    fn evict_supported(&self, group_id: &str) -> bool {
        hydration::evict_gate(&self.state, group_id, "").is_ok()
    }

    fn evict(&self, group_id: &str, path: &str) -> Result<EvictOutcome, SyncError> {
        let path = path.trim_end_matches('/');
        let result = if directory::is_indexed_directory(&self.state, group_id, path)? {
            directory::evict_directory(&self.state, group_id, path).map(|outcome| EvictOutcome {
                dehydrated: outcome.evicted_files > 0,
                blocks_reclaimed: outcome.blocks_reclaimed,
                bytes_reclaimed: outcome.bytes_reclaimed,
            })
        } else {
            hydration::evict(&self.state, group_id, path).map(|outcome| EvictOutcome {
                dehydrated: outcome.dehydrated,
                blocks_reclaimed: outcome.blocks_reclaimed,
                bytes_reclaimed: outcome.bytes_reclaimed,
            })
        };
        // The path has settled, whatever the outcome (completed, aborted, or
        // failed): a lease acquired for an eviction that did not complete is
        // released by the reconciler now rather than at the next restart.
        self.state.nudge_custody_hold_reconciler();
        result
    }

    fn status(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationStatusSummary>, SyncError> {
        let path = path.trim_end_matches('/');
        let is_directory = directory::is_indexed_directory(&self.state, group_id, path)?;
        let info = if is_directory {
            Some(directory::directory_status(&self.state, group_id, path)?)
        } else {
            hydration::materialization_status(&self.state, group_id, path)?
        };
        // `Present` over an object that is not the current version's content
        // (an older version's bytes under a newer row) is an object that
        // stands without current content: the two facts are reported apart.
        // Fail closed: a kind or proof that cannot be read is not evidence.
        let content_is_current = || {
            if is_directory {
                return true;
            }
            let kind = self
                .state
                .replica_coordinator
                .file_index_repository()
                .get_record_kind(group_id, path)
                .ok()
                .flatten();
            match kind {
                None => false,
                Some(kind) if kind != yadorilink_replica_domain::file::RecordKind::File => true,
                Some(_) => self
                    .state
                    .replica_coordinator
                    .local_copy_names_current_version(group_id, path)
                    .unwrap_or(false),
            }
        };
        Ok(info.and_then(|info| {
            let exact = info.state == MaterializationState::Present && content_is_current();
            crate::shell_status::local_presence(Some(info.state), exact)
                .map(|state| MaterializationStatusSummary { state })
        }))
    }

    fn pin<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<PinOutcome, SyncError>> {
        Box::pin(async move {
            let path = path.trim_end_matches('/');
            // Recorded first, and before anything is fetched: the pin is the user's request, and
            // it stands whether or not the download that follows succeeds. Every eviction check
            // that starts after this row exists sees it (a folder's row covers files that appear
            // later, by path prefix). The evictions already past their check hold their file's
            // lock to their end, and every such file exists now, so listing the files after the
            // row and taking their locks drains exactly those; the fetch below then brings the
            // file back (a provider folder has nothing to fetch, but nothing new is evicted).
            let coordinator = &self.state.replica_coordinator;
            coordinator.pinned_item_repository().pin(group_id, path)?;
            {
                let mut covered = vec![path.to_owned()];
                if directory::is_indexed_directory(&self.state, group_id, path)? {
                    covered.extend(
                        coordinator
                            .file_index_repository()
                            .list_live_files_under(group_id, path)?,
                    );
                }
                for covered_path in lock_order(covered) {
                    let lock = coordinator.path_lock_registry().path_lock(group_id, &covered_path);
                    drop(lock.lock_owned().await);
                }
            }
            let retention = self.retention(group_id, path)?;
            // A provider folder's content is fetched by the OS, never by the daemon. On macOS the
            // app's File Provider host asks the OS for every kept file (the provider Eager driver
            // answers its download queries with them), also after the user removes a download in
            // Finder; no other platform does.
            let download_error = if crate::provider_gate::require_filesystem_root(
                &self.state.replica_coordinator,
                group_id,
            )
            .is_err()
            {
                (!cfg!(target_os = "macos")).then(|| {
                    "the files of this folder are downloaded by the operating system; the pin is \
                     recorded but does not download them"
                        .to_owned()
                })
            } else {
                self.fetch_kept(group_id, path).await.err().map(|e| e.to_string())
            };
            Ok(PinOutcome { retention, download_error })
        })
    }

    fn unpin(&self, group_id: &str, path: &str) -> Result<RetentionState, SyncError> {
        let path = path.trim_end_matches('/');
        let coordinator = &self.state.replica_coordinator;
        coordinator.pinned_item_repository().unpin(group_id, path)?;
        self.retention(group_id, path)
    }

    fn retention(&self, group_id: &str, path: &str) -> Result<RetentionState, SyncError> {
        let path = path.trim_end_matches('/');
        let retention =
            self.state.replica_coordinator.pinned_item_repository().retention(group_id, path)?;
        Ok(RetentionState {
            pinned: retention.policy == yadorilink_sync_sqlite::RetentionPolicy::Pinned,
            explicit: retention.explicit,
        })
    }
}
