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
use crate::runtime_telemetry::PinnedPending;
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

/// The first wait after a pass in which a pinned item could not be downloaded; it doubles up to
/// [`RETRY_MAX`] while the failure lasts.
const RETRY_MIN: std::time::Duration = std::time::Duration::from_secs(5);
const RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(600);
/// How often a settled pinned folder is looked at again, for files that arrived under it.
const RECHECK: std::time::Duration = std::time::Duration::from_secs(600);

/// The groups whose link is live: a paused folder transfers nothing, and a pin whose folder is
/// unlinked has nowhere to download to.
fn active_groups(state: &Arc<DaemonState>) -> Option<std::collections::HashSet<String>> {
    match state.replica_coordinator.link_repository().list_links() {
        Ok(links) => Some(
            links
                .into_iter()
                .filter(|link| !link.paused && !link.orphaned)
                .map(|link| link.group_id)
                .collect(),
        ),
        Err(error) => {
            tracing::warn!(%error, "links could not be listed for pinned downloads");
            None
        }
    }
}

/// One download pass over every pinned item on a folder the daemon hydrates itself. Records
/// what could not be downloaded for status as each folder finishes, and returns whether
/// anything failed. `next_wait` is the wait that follows a failed pass.
pub(crate) async fn retry_pass(state: &Arc<DaemonState>, next_wait: std::time::Duration) -> bool {
    let mut pinned = match state.replica_coordinator.retention_rules().list_all() {
        Ok(pinned) => pinned,
        Err(error) => {
            tracing::warn!(%error, "pinned items could not be listed for download");
            return true;
        }
    };
    // One folder at a time, so its state can be published when it is done.
    pinned.sort();
    let adapter = DaemonMaterializationAdapter::new(state.clone());
    let mut visited: std::collections::HashSet<String> = Default::default();
    let mut failed = false;
    let mut current: Option<(String, Option<PinnedPending>)> = None;
    let publish = |group: String, pending: Option<PinnedPending>| {
        state.telemetry.set_pinned_group(&group, pending);
    };
    for (group_id, path) in pinned {
        if current.as_ref().is_some_and(|(group, _)| *group != group_id) {
            if let Some((group, pending)) = current.take() {
                publish(group, pending);
            }
        }
        // Pause is looked at before every item, so a folder paused mid-pass stops at once.
        let Some(active) = active_groups(state) else {
            failed = true;
            break;
        };
        if !active.contains(&group_id)
            || crate::provider_gate::require_filesystem_root(&state.replica_coordinator, &group_id)
                .is_err()
        {
            // Paused or unlinked part-way: nothing of this folder is shown as pending.
            visited.remove(&group_id);
            if current.as_ref().is_some_and(|(group, _)| *group == group_id) {
                current = None;
            }
            continue;
        }
        visited.insert(group_id.clone());
        let entry = current.get_or_insert_with(|| (group_id.clone(), None));
        // A pinned path that no longer exists (deleted, or a folder with no files left) has
        // nothing to download.
        if let Err(error) = adapter.fetch_kept(&group_id, &path).await {
            if matches!(error, SyncError::NotFound(_)) {
                continue;
            }
            tracing::info!(%error, group_id, path, "pinned item not downloaded yet; will retry");
            failed = true;
            let pending = entry.1.get_or_insert_with(|| PinnedPending {
                items: 0,
                last_error: String::new(),
                next_retry: std::time::Instant::now() + next_wait,
            });
            pending.items += 1;
            pending.last_error = error.to_string();
            // Shown now, not when the folder ends: the next item may take a long time.
            state.telemetry.set_pinned_group(&group_id, Some(pending.clone()));
        }
    }
    if let Some((group, pending)) = current.take() {
        publish(group, pending);
    }
    // The wait begins here, not when the pass started.
    state.telemetry.finish_pinned_pass(&visited, std::time::Instant::now() + next_wait);
    failed
}

/// Keeps pinned items downloaded for the life of the daemon: a pass at startup, again after a
/// growing wait while an item fails (5 s doubling to 10 min), at once when a peer registers, and
/// every 10 minutes otherwise for files that arrived under a pinned folder. Holds only a weak
/// reference, so it never keeps the daemon alive.
pub(crate) fn spawn_pinned_download_retry(state: &Arc<DaemonState>) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(state);
    let mut registrations = state.peers.subscribe_to_registrations();
    let wake = state.telemetry.pinned_download_wake();
    tokio::spawn(async move {
        let mut backoff = RETRY_MIN;
        loop {
            let Some(state) = weak.upgrade() else {
                return;
            };
            // The wait is known only after the pass, but the pass records it for status: assume
            // the backoff step and keep it if the pass fails.
            let wait = if retry_pass(&state, backoff).await {
                let wait = backoff;
                backoff = (backoff * 2).min(RETRY_MAX);
                wait
            } else {
                backoff = RETRY_MIN;
                RECHECK
            };
            drop(state);
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = wake.notified() => {}
                changed = registrations.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    backoff = RETRY_MIN;
                }
            }
        }
    })
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
            self.hydrate(group_id, path).await.map(|_| ())
        }
    }

    /// Makes the store hold the current versions the pin keeps, from the files that hold them
    /// (`store_residency`): a version this device received, or captured as a hash only, is held by
    /// its file alone, and the user's next edit would replace it. The pin stands whatever this
    /// finds. A file that is not the version it was recorded as is journaled for capture, which now
    /// goes into the store because the item is pinned; the answer says so, so that the user can
    /// pin again once it has settled instead of finding out when an edit loses a version.
    async fn keep_versions_in_store(&self, group_id: &str, path: &str) -> Option<&'static str> {
        match crate::store_residency::bring_current_versions_into_daemon_store(
            &self.state,
            group_id,
            path,
        )
        .await
        {
            Ok(crate::store_residency::Residency::InStore) => None,
            Ok(crate::store_residency::Residency::Pending(paths, _)) => {
                tracing::info!(
                    group_id,
                    path,
                    pending = paths.len(),
                    "pinned: files are being captured into the block store"
                );
                Some("changing_retry")
            }
            Err(error) => {
                tracing::warn!(%error, group_id, path, "pinned, but the current versions could not be brought into the block store");
                Some("not_kept_error")
            }
        }
    }

    /// Records an `online_only` rule at `path`. The apply pass frees the copies and the Eager
    /// driver stops offering them. Only a provider folder has an OS copy to free.
    fn online_only_rule(&self, group_id: &str, path: &str) -> Result<PinOutcome, SyncError> {
        let coordinator = &self.state.replica_coordinator;
        if crate::provider_gate::require_filesystem_root(coordinator, group_id).is_ok() {
            return Err(SyncError::InvalidInput(
                "online only is available in File Provider folders; this folder keeps its files \
                 on disk"
                    .to_owned(),
            ));
        }
        coordinator.retention_rules().set(
            group_id,
            path,
            Some(yadorilink_sync_sqlite::Rule::OnlineOnly),
        )?;
        Ok(PinOutcome {
            retention: self.retention(group_id, path)?,
            download_error: None,
            history_not_kept_reason: None,
        })
    }

    /// Removes the rule set at exactly `path`.
    fn default_rule(&self, group_id: &str, path: &str) -> Result<PinOutcome, SyncError> {
        let coordinator = &self.state.replica_coordinator;
        coordinator.retention_rules().set(group_id, path, None)?;
        // The item may have been pending: the next pass drops it from the status.
        self.state.telemetry.pinned_download_wake().notify_one();
        Ok(PinOutcome {
            retention: self.retention(group_id, path)?,
            download_error: None,
            history_not_kept_reason: None,
        })
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
                hydration::Materialized::InPlace(_) => Err(SyncError::CorruptState(
                    "a temp materialization produced an in-place result".into(),
                )),
            }
        })
    }

    fn hydrate<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<bool, SyncError>> {
        Box::pin(async move {
            let path = path.trim_end_matches('/');
            let result = if directory::is_indexed_directory(&self.state, group_id, path)? {
                directory::hydrate_directory(&self.state, group_id, path).await
            } else {
                hydration::materialize_path(&self.state, group_id, path, hydration::Sink::InPlace)
                    .await
                    .and_then(|materialized| match materialized {
                        hydration::Materialized::InPlace(fetched) => Ok(fetched),
                        hydration::Materialized::Temp(_) => Err(SyncError::CorruptState(
                            "an in-place hydration produced a temp result".into(),
                        )),
                    })
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
                not_freed: None,
            })
        } else {
            hydration::evict(&self.state, group_id, path).map(|outcome| EvictOutcome {
                dehydrated: outcome.dehydrated,
                blocks_reclaimed: outcome.blocks_reclaimed,
                bytes_reclaimed: outcome.bytes_reclaimed,
                not_freed: outcome.not_freed.map(|why| why.code()),
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

    fn set_rule<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        rule: crate::application::ports::RuleChoice,
    ) -> BoxFuture<'a, Result<PinOutcome, SyncError>> {
        use crate::application::ports::RuleChoice;
        Box::pin(async move {
            let path = path.trim_end_matches('/');
            match rule {
                RuleChoice::Keep => {}
                RuleChoice::OnlineOnly => return self.online_only_rule(group_id, path),
                RuleChoice::Default => return self.default_rule(group_id, path),
            }
            // Recorded first, and before anything is fetched: the pin is the user's request, and
            // it stands whether or not the download that follows succeeds. Every eviction check
            // that starts after this row exists sees it (a folder's row covers files that appear
            // later, by path prefix). The evictions already past their check hold their file's
            // lock to their end, and every such file exists now, so listing the files after the
            // row and taking their locks drains exactly those; the fetch below then brings the
            // file back (a provider folder has nothing to fetch, but nothing new is evicted).
            let coordinator = &self.state.replica_coordinator;
            coordinator.retention_rules().set(
                group_id,
                path,
                Some(yadorilink_sync_sqlite::Rule::Keep),
            )?;
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
            let mut history_not_kept_reason = None;
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
                (!cfg!(target_vendor = "apple")).then(|| {
                    "the files of this folder are downloaded by the operating system; the pin is \
                     recorded but does not download them"
                        .to_owned()
                })
            } else {
                // A file this device holds only as bytes in the folder is read into the store
                // before the download, so that the download finds the blocks it needs locally
                // instead of asking peers for content this device already has. Whether the store
                // holds the versions is answered after the download, when a placeholder has also
                // become a file.
                let _ = self.keep_versions_in_store(group_id, path).await;
                let error = self
                    .fetch_kept(group_id, path)
                    .await
                    .err()
                    .map(|e| format!("{e}. It will be retried automatically"));
                history_not_kept_reason = self.keep_versions_in_store(group_id, path).await;
                error
            };
            if download_error.is_some() {
                // Shown as pending at once, and retried without waiting for the next pass.
                self.state.telemetry.pinned_download_wake().notify_one();
            }
            Ok(PinOutcome { retention, download_error, history_not_kept_reason })
        })
    }

    fn retention(&self, group_id: &str, path: &str) -> Result<RetentionState, SyncError> {
        let path = path.trim_end_matches('/');
        let retention =
            self.state.replica_coordinator.retention_rules().retention(group_id, path)?;
        Ok(RetentionState {
            pinned: retention.policy == yadorilink_sync_sqlite::RetentionPolicy::Pinned,
            online_only: retention.policy == yadorilink_sync_sqlite::RetentionPolicy::OnlineOnly,
            explicit: retention.explicit,
        })
    }
}
